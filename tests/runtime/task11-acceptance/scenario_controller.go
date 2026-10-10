package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

var errScenarioController = errors.New("fixed scenario controller operation refused")
var scenarioCases = []string{"native-accounting", "eap-unenrolled", "ongoing-interim", "ongoing-stop", "duplicate-pair", "ha-primary", "postgres-outage", "business-outage", "ca-ec-continuity", "ca-rsa-continuity"}

type scenarioNASPrior struct {
	SelectionBytes []byte `json:"selection_bytes"`
	ResultBytes    []byte `json:"result_bytes"`
}
type scenarioNASInput struct {
	Schema        int               `json:"schema"`
	RequestBytes  []byte            `json:"request_bytes"`
	RequestSHA256 string            `json:"request_sha256"`
	PlanBytes     []byte            `json:"plan_bytes"`
	PlanSHA256    string            `json:"plan_sha256"`
	Prior         *scenarioNASPrior `json:"prior,omitempty"`
}
type scenarioAdmission struct {
	Schema             int       `json:"schema"`
	RequestSHA256      string    `json:"request_sha256"`
	PlanSHA256         string    `json:"plan_sha256"`
	PlatformSHA256     string    `json:"platform_sha256"`
	EnrollmentSHA256   string    `json:"enrollment_sha256"`
	ApplicationSHA256  string    `json:"application_sha256"`
	ScenarioSHA256     string    `json:"scenario_sha256"`
	OriginalSeedSHA256 string    `json:"original_seed_sha256"`
	CollectionEpoch    time.Time `json:"collection_epoch"`
	Node               string    `json:"node"`
	Session            string    `json:"session"`
	Case               string    `json:"case"`
	Authority          string    `json:"authority,omitempty"`
}

// Dispatch shares the sole strict Stage decoder with the driver. Neither branch
// accepts an arbitrary stage or silently drops scenario coordinates.
func dispatchRequestedStage(ctx context.Context, raw []byte, legacy func(context.Context, string) error, scenario func(context.Context, sc.Stage) error) error {
	stage, err := sc.DecodeStage(raw)
	if err != nil || ctx.Err() != nil {
		return errScenarioController
	}
	if stage.Stage == "scenario-operation" {
		if scenario == nil {
			return errScenarioController
		}
		return scenario(ctx, stage)
	}
	if legacy == nil {
		return errScenarioController
	}
	return legacy(ctx, stage.Stage)
}

func selectScenarioPlan(pin string, read func(string, int64, int) ([]byte, error)) (string, []byte, error) {
	if !validSHA(pin) || read == nil {
		return "", nil, errScenarioController
	}
	var name string
	var selected []byte
	for _, candidate := range scenarioCases {
		raw, err := read(control+"/scenarios/plans/"+candidate+".json", 64<<10, 0)
		if errors.Is(err, os.ErrNotExist) {
			clear(raw)
			continue
		}
		if err != nil || len(raw) > 64<<10 {
			clear(raw)
			clear(selected)
			return "", nil, errScenarioController
		}
		if adoption.Digest(raw) == pin {
			if selected != nil {
				clear(raw)
				clear(selected)
				return "", nil, errScenarioController
			}
			name = candidate
			selected = raw
		} else {
			clear(raw)
		}
	}
	if selected == nil {
		return "", nil, errScenarioController
	}
	return name, selected, nil
}
func scenarioPrivateInput(claim *scenarioClaim, plan, selection, prior []byte) ([]byte, error) {
	if claim == nil || claim.store == nil || len(plan) > 64<<10 {
		return nil, errScenarioController
	}
	r := claim.request
	if adoption.Digest(plan) != r.PlanSHA256 {
		return nil, errScenarioController
	}
	required := r.Authority == "rsa" && (r.Action == "nas-ca-adopted" || r.Action == "nas-ca-passive")
	if !required && (len(selection) != 0 || len(prior) != 0) {
		return nil, errScenarioController
	}
	if required {
		stored, _, err := claim.ReadCASelection()
		same := err == nil && bytes.Equal(stored, selection)
		clear(stored)
		if !same || len(prior) == 0 || len(prior) > 32<<10 {
			return nil, errScenarioController
		}
	}
	claim.store.mu.Lock()
	defer claim.store.mu.Unlock()
	if _, err := claim.recheck(); err != nil {
		return nil, errScenarioController
	}
	in := scenarioNASInput{Schema: 1, RequestBytes: claim.raw, RequestSHA256: claim.sha, PlanBytes: plan, PlanSHA256: r.PlanSHA256}
	if required {
		stored, err := claim.store.read("results", fmt.Sprintf("%s-%d.json", r.AttemptID, r.IssuanceSequence), sc.MaxResultBytes)
		same := err == nil && bytes.Equal(stored, prior)
		clear(stored)
		if !same {
			return nil, errScenarioController
		}
		in.Prior = &scenarioNASPrior{SelectionBytes: selection, ResultBytes: prior}
	}
	raw, err := json.Marshal(in)
	if err != nil || len(raw) > nasInputLimit {
		clear(raw)
		return nil, errScenarioController
	}
	return raw, nil
}
func validateScenarioAdmission(raw []byte, claim *scenarioClaim, caseName, seedSHA string, epoch time.Time) (scenarioAdmission, error) {
	var a scenarioAdmission
	var fields map[string]json.RawMessage
	if claim == nil || !slices.Contains(scenarioCases, caseName) || !validSHA(seedSHA) || epoch.IsZero() || len(raw) > 4096 || decodeExactJSON(raw, &a) != nil || decodeExactJSON(raw, &fields) != nil {
		return a, errScenarioController
	}
	r := claim.request
	expected := []string{"schema", "request_sha256", "plan_sha256", "platform_sha256", "enrollment_sha256", "application_sha256", "scenario_sha256", "original_seed_sha256", "collection_epoch", "node", "session", "case"}
	authority := ""
	if caseName == "ca-ec-continuity" {
		authority = "ec"
	}
	if caseName == "ca-rsa-continuity" {
		authority = "rsa"
	}
	if authority != "" {
		expected = append(expected, "authority")
	}
	if len(fields) != len(expected) {
		return a, errScenarioController
	}
	for _, key := range expected {
		if fields[key] == nil {
			return a, errScenarioController
		}
	}
	_, offset := a.CollectionEpoch.Zone()
	if a.Schema != 1 || a.RequestSHA256 != claim.sha || a.PlanSHA256 != r.PlanSHA256 || a.PlatformSHA256 != r.PlatformSHA256 || a.EnrollmentSHA256 != r.EnrollmentSHA256 || a.ApplicationSHA256 != r.ApplicationSHA256 || a.ScenarioSHA256 != r.ScenarioSHA256 || a.OriginalSeedSHA256 != seedSHA || !a.CollectionEpoch.Equal(epoch) || offset != 0 || a.CollectionEpoch.Nanosecond() != 0 || a.Case != caseName || a.Authority != authority || (r.Authority != "" && r.Authority != authority) {
		return a, errScenarioController
	}
	selector := r
	selector.Action = "read-accounting"
	selector.Node = a.Node
	selector.Sessions = []string{a.Session}
	selector.Authority = ""
	selector.SelectionSHA256 = ""
	selector.IssuanceSequence = 0
	if selector.Validate() != nil {
		return a, errScenarioController
	}
	if r.Action == "read-accounting" && (r.Node != a.Node || len(r.Sessions) != 1 || r.Sessions[0] != a.Session) {
		return a, errScenarioController
	}
	return a, nil
}

// Compare the exact physical snapshot with loaded state. Only the independently
// validated in-memory phase overlay is excluded; raw bytes remain the SHA input.
func validateScenarioPhysicalEnrollment(raw []byte, loaded enrollment) error {
	var physical enrollment
	if len(raw) == 0 || len(raw) > 64<<10 || decodeExactJSON(raw, &physical) != nil || len(physical.Passive.Manifests) != 0 {
		return errScenarioController
	}
	// These enrollment structs use their existing Go field names as the JSON ABI.
	// The duplicate parser is already strict; this local walk rejects aliases in
	// those exact structs rather than encoding/json's case-insensitive matches.
	var canonical func([]byte, reflect.Type) bool
	canonical = func(body []byte, typ reflect.Type) bool {
		switch typ.Kind() {
		case reflect.Struct:
			var fields map[string]json.RawMessage
			if decodeExactJSON(body, &fields) != nil || len(fields) != typ.NumField() {
				return false
			}
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				value, ok := fields[field.Name]
				if !ok || !canonical(value, field.Type) {
					return false
				}
			}
		case reflect.Map:
			if bytes.Equal(bytes.TrimSpace(body), []byte("null")) {
				return typ.Elem().Kind() == reflect.String
			}
			var members map[string]json.RawMessage
			if decodeExactJSON(body, &members) != nil || members == nil {
				return false
			}
			for _, value := range members {
				if !canonical(value, typ.Elem()) {
					return false
				}
			}
		case reflect.String:
			var value string
			if bytes.Equal(bytes.TrimSpace(body), []byte("null")) || decodeExactJSON(body, &value) != nil {
				return false
			}
		}
		return true
	}
	if !canonical(raw, reflect.TypeFor[enrollment]()) {
		return errScenarioController
	}
	if loaded.Passive.Manifests != nil && validatePassivePhasePins(loaded.Passive.Manifests) != nil {
		return errScenarioController
	}
	physical.Passive.Manifests = nil
	loaded.Passive.Manifests = nil
	if !reflect.DeepEqual(physical, loaded) {
		return errScenarioController
	}
	return nil
}
