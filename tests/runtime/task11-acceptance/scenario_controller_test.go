package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

func TestRequestedStageRoutesExactScenarioAndRefusesAliases(t *testing.T) {
	stage := recordStage(recordRequest(1, "intake-ready"), []byte("request"))
	legacy, scenario := 0, 0
	old := func(context.Context, string) error { legacy++; return nil }
	next := func(_ context.Context, got sc.Stage) error {
		scenario++
		if got != stage {
			t.Fatal("scenario coordinates changed")
		}
		return nil
	}
	if err := dispatchRequestedStage(context.Background(), recordJSON(t, stage), old, next); err != nil {
		t.Fatal(err)
	}
	if scenario != 1 || legacy != 0 {
		t.Fatal("scenario bypassed exact dispatch")
	}
	if err := dispatchRequestedStage(context.Background(), []byte(`{"stage":"keys"}`), old, next); err != nil || legacy != 1 {
		t.Fatal("legacy stage unavailable", err)
	}
	for _, raw := range []string{`{"Stage":"keys"}`, `{"stage":"keys","attempt_id":""}`, `{"stage":"keys","stage":"keys"}`, `{"stage":"all"}`, `{"stage":"keys"}{}`, `{"stage":"scenario-operation"}`} {
		if dispatchRequestedStage(context.Background(), []byte(raw), old, next) == nil {
			t.Fatalf("invalid service input accepted: %s", raw)
		}
	}
}
func TestScenarioPlanSelectionOnlyReadsClosedPrivateFiles(t *testing.T) {
	raw := []byte(" \n{\"private\":true}\n")
	target := control + "/scenarios/plans/ca-ec-continuity.json"
	reads := 0
	read := func(path string, limit int64, uid int) ([]byte, error) {
		reads++
		if limit != 64<<10 || uid != 0 || !strings.HasPrefix(path, control+"/scenarios/plans/") {
			t.Fatal("unbounded or foreign plan path")
		}
		if path == target {
			return bytes.Clone(raw), nil
		}
		return nil, os.ErrNotExist
	}
	name, got, err := selectScenarioPlan(adoption.Digest(raw), read)
	if err != nil || name != "ca-ec-continuity" || !bytes.Equal(got, raw) || reads != 10 {
		t.Fatal("exact immutable plan not selected", name, err, reads)
	}
	for _, kind := range []string{"missing", "duplicate", "read-error", "oversize", "pin"} {
		t.Run(kind, func(t *testing.T) {
			fn := func(path string, _ int64, _ int) ([]byte, error) {
				if kind == "read-error" {
					return nil, errors.New("private failure")
				}
				if kind == "duplicate" {
					return bytes.Clone(raw), nil
				}
				if path == target && kind == "oversize" {
					return bytes.Repeat([]byte("x"), 65537), nil
				}
				if path == target && kind != "missing" {
					return bytes.Clone(raw), nil
				}
				return nil, os.ErrNotExist
			}
			pin := adoption.Digest(raw)
			if kind == "pin" {
				pin = "../outside"
			}
			if _, _, err := selectScenarioPlan(pin, fn); err == nil {
				t.Fatal("ambiguous or invalid private plan accepted")
			}
		})
	}
}
func TestScenarioPrivatePipePreservesClaimAndOpaquePriorBytes(t *testing.T) {
	root := recordFixture(t)
	r := recordRequest(1, "nas-native")
	plan := []byte("\n{\"private\":true}\n")
	r.PlanSHA256 = adoption.Digest(plan)
	request := append(recordJSON(t, r), '\n')
	recordWrite(t, root, "requests", r, request)
	claim, err := recordOpen(t, root).Admit(recordStage(r, request), r.Pins)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := scenarioPrivateInput(claim, plan, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var in scenarioNASInput
	if json.Unmarshal(raw, &in) != nil || in.Schema != 1 || !bytes.Equal(in.RequestBytes, request) || !bytes.Equal(in.PlanBytes, plan) || in.RequestSHA256 != adoption.Digest(request) || in.Prior != nil {
		t.Fatal("protected bytes reconstructed")
	}
	// Caller-visible claim fields cannot rewrite the private admitted input.
	claim.Request.Action = "nas-outage"
	claim.RequestRaw[0] = 'x'
	claim.RequestSHA256 = strings.Repeat("0", 64)
	again, err := scenarioPrivateInput(claim, plan, nil, nil)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("public claim copy changed private handoff", err)
	}
	if _, err := scenarioPrivateInput(claim, []byte("changed"), nil, nil); err == nil {
		t.Fatal("changed plan accepted")
	}
	if _, err := scenarioPrivateInput(claim, plan, []byte("{}"), []byte("{}")); err == nil {
		t.Fatal("irrelevant prior accepted")
	}
}
func TestScenarioAdmissionBindsPhysicalCaseSeedEpochAndProtectedClaim(t *testing.T) {
	root := recordFixture(t)
	r := recordRequest(1, "nas-native")
	request := recordJSON(t, r)
	recordWrite(t, root, "requests", r, request)
	claim, err := recordOpen(t, root).Admit(recordStage(r, request), r.Pins)
	if err != nil {
		t.Fatal(err)
	}
	epoch := time.Unix(1800000000, 0).UTC()
	seed := strings.Repeat("f", 64)
	a := scenarioAdmission{Schema: 1, RequestSHA256: adoption.Digest(request), PlanSHA256: r.PlanSHA256, PlatformSHA256: r.PlatformSHA256, EnrollmentSHA256: r.EnrollmentSHA256, ApplicationSHA256: r.ApplicationSHA256, ScenarioSHA256: r.ScenarioSHA256, OriginalSeedSHA256: seed, CollectionEpoch: epoch, Node: "green-primary", Session: "task11-one", Case: "native-accounting"}
	if _, err := validateScenarioAdmission(recordJSON(t, a), claim, a.Case, seed, epoch); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"request", "plan", "platform", "enrollment", "application", "helper", "seed", "epoch", "case", "node", "session", "authority", "alias", "missing", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			bad := a
			switch kind {
			case "request":
				bad.RequestSHA256 = strings.Repeat("0", 64)
			case "plan":
				bad.PlanSHA256 = strings.Repeat("0", 64)
			case "platform":
				bad.PlatformSHA256 = strings.Repeat("0", 64)
			case "enrollment":
				bad.EnrollmentSHA256 = strings.Repeat("0", 64)
			case "application":
				bad.ApplicationSHA256 = strings.Repeat("0", 64)
			case "helper":
				bad.ScenarioSHA256 = strings.Repeat("0", 64)
			case "seed":
				bad.OriginalSeedSHA256 = strings.Repeat("0", 64)
			case "epoch":
				bad.CollectionEpoch = epoch.Add(time.Second)
			case "case":
				bad.Case = "ha-primary"
			case "node":
				bad.Node = "blue-primary"
			case "session":
				bad.Session = "foreign"
			case "authority":
				bad.Authority = "ec"
			}
			raw := recordJSON(t, bad)
			if kind == "alias" {
				raw = bytes.Replace(raw, []byte(`"schema":`), []byte(`"Schema":`), 1)
			}
			if kind == "missing" {
				var fields map[string]json.RawMessage
				_ = json.Unmarshal(raw, &fields)
				delete(fields, "node")
				raw = recordJSON(t, fields)
			}
			if kind == "unknown" {
				raw = append([]byte(`{"pass":true,`), raw[1:]...)
			}
			if _, err := validateScenarioAdmission(raw, claim, a.Case, seed, epoch); err == nil {
				t.Fatal("unbound public admission accepted")
			}
		})
	}
}

func TestScenarioControllerPublicEntryRefusesUnpinnedStage(t *testing.T) {
	if err := executeScenarioStage(context.Background(), sc.Stage{}); err == nil {
		t.Fatal("unbound controller stage accepted")
	}
}
func TestScenarioPhysicalEnrollmentBindsLoadedSnapshotWithoutRewriting(t *testing.T) {
	e := enrollment{Schema: 1, ApplicationSHA256: strings.Repeat("a", 64), ControllerSHA256: strings.Repeat("b", 64), Nodes: map[string]nodeEnrollment{"blue-primary": {MachineID: strings.Repeat("c", 32), Hostname: "task11-blue-primary", ConfigSHA256: strings.Repeat("d", 64), Pin: strings.Repeat("e", 64)}}}
	e.Cloud.InstalledSeedSHA256 = strings.Repeat("f", 64)
	raw := append(recordJSON(t, e), '\n')
	before := bytes.Clone(raw)
	loaded := e
	loaded.Passive.Manifests = map[string]string{"green-primary-prepared": strings.Repeat("a", 64)}
	if err := validateScenarioPhysicalEnrollment(raw, loaded); err != nil || !bytes.Equal(raw, before) {
		t.Fatal("valid phase overlay rewrote or refused physical enrollment", err)
	}
	for _, kind := range []string{"cloud", "node", "physical-phase", "invalid-overlay", "alias", "duplicate", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			physical := e
			physical.Nodes = map[string]nodeEnrollment{}
			for name, node := range e.Nodes {
				physical.Nodes[name] = node
			}
			current := loaded
			current.Passive.Manifests = map[string]string{"green-primary-prepared": strings.Repeat("a", 64)}
			switch kind {
			case "cloud":
				physical.Cloud.InstalledSeedSHA256 = strings.Repeat("0", 64)
			case "node":
				node := physical.Nodes["blue-primary"]
				node.Pin = strings.Repeat("0", 64)
				physical.Nodes["blue-primary"] = node
			case "physical-phase":
				physical.Passive.Manifests = map[string]string{"green-primary-prepared": strings.Repeat("a", 64)}
			case "invalid-overlay":
				current.Passive.Manifests = map[string]string{"unknown": strings.Repeat("a", 64)}
			}
			candidate := recordJSON(t, physical)
			switch kind {
			case "alias":
				candidate = bytes.Replace(candidate, []byte(`"Schema":`), []byte(`"schema":`), 1)
			case "duplicate":
				candidate = append([]byte(`{"Schema":1,`), candidate[1:]...)
			case "oversize":
				candidate = append(candidate, bytes.Repeat([]byte(" "), 65537)...)
			}
			if validateScenarioPhysicalEnrollment(candidate, current) == nil {
				t.Fatal("mixed physical/loaded enrollment accepted")
			}
		})
	}
}
