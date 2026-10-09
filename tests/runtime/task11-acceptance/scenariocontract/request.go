// Package scenariocontract is the development-only closed controller wire contract.
// It is not linked into the shipping daemon and cannot execute operations.
package scenariocontract

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

const (
	MaxRequestBytes = 64 << 10
	MaxResultBytes  = 8 << 20
	MaxOpaqueBytes  = 5 << 20
	MaxSequence     = 24
)

type Pins struct {
	PlanSHA256        string `json:"plan_sha256"`
	PlatformSHA256    string `json:"platform_sha256"`
	EnrollmentSHA256  string `json:"enrollment_sha256"`
	ApplicationSHA256 string `json:"application_sha256"`
	ScenarioSHA256    string `json:"scenario_sha256"`
}

type Request struct {
	Schema    int    `json:"schema"`
	AttemptID string `json:"attempt_id"`
	Sequence  int    `json:"sequence"`
	Action    string `json:"action"`
	Pins
	Node             string   `json:"node,omitempty"`
	Sessions         []string `json:"sessions,omitempty"`
	Authority        string   `json:"authority,omitempty"`
	SelectionSHA256  string   `json:"selection_sha256,omitempty"`
	IssuanceSequence int      `json:"issuance_sequence,omitempty"`
}

type Stage struct {
	Stage         string `json:"stage"`
	AttemptID     string `json:"attempt_id,omitempty"`
	Sequence      int    `json:"sequence,omitempty"`
	RequestSHA256 string `json:"request_sha256,omitempty"`
}

var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var attemptPattern = regexp.MustCompile(`^task11-[0-9a-f]{32}$`)
var sessionPattern = regexp.MustCompile(`^task11-[a-z0-9-]{1,57}$`)
var serialPattern = regexp.MustCompile(`^[1-9][0-9]{0,63}$`)

func (p Pins) validate() error {
	for _, s := range []string{p.PlanSHA256, p.PlatformSHA256, p.EnrollmentSHA256, p.ApplicationSHA256, p.ScenarioSHA256} {
		if !hashPattern.MatchString(s) {
			return errors.New("independent input pins required")
		}
	}
	return nil
}
func bodyKind(action string) string {
	switch action {
	case "probe-active-pair":
		return "probe"
	case "read-accounting":
		return "ledger"
	case "stop-green-primary", "start-green-primary", "reboot-green-primary":
		return "lifecycle"
	case "nas-native", "nas-ongoing", "nas-duplicates", "nas-outage":
		return "nas"
	case "nas-ca-original", "nas-ca-adopted", "nas-ca-passive":
		return "ca"
	case "read-ca-issued":
		return "ca_issued"
	case "stop-postgres", "start-postgres", "intake-unavailable", "intake-ready":
		return "gate"
	case "probe-owned-cleanup":
		return "cleanup"
	default:
		return ""
	}
}

// This selector identifies an earlier protected result; the controller must
// independently verify genuine prior issuance and exact selection bytes.
func (r Request) requiresCASelection() bool {
	return r.Action == "read-ca-issued" || (r.Authority == "rsa" && (r.Action == "nas-ca-adopted" || r.Action == "nas-ca-passive"))
}
func (r Request) Validate() error {
	if r.Schema != 1 || !attemptPattern.MatchString(r.AttemptID) || r.Sequence < 1 || r.Sequence > MaxSequence || bodyKind(r.Action) == "" {
		return errors.New("closed scenario envelope required")
	}
	if e := r.validate(); e != nil {
		return e
	}
	switch bodyKind(r.Action) {
	case "ledger":
		if (r.Node != "green-primary" && r.Node != "green-secondary") || len(r.Sessions) < 1 || len(r.Sessions) > 8 {
			return errors.New("closed green accounting selector required")
		}
		seen := map[string]bool{}
		for _, s := range r.Sessions {
			if !sessionPattern.MatchString(s) || seen[s] {
				return errors.New("unique bounded accounting sessions required")
			}
			seen[s] = true
		}
	case "lifecycle":
		if r.Node != "green-primary" || len(r.Sessions) != 0 {
			return errors.New("only the original green-primary unit may be controlled")
		}
	default:
		if r.Node != "" || len(r.Sessions) != 0 {
			return errors.New("irrelevant node/session selector refused")
		}
	}
	if bodyKind(r.Action) == "ca" {
		if r.Authority != "ec" && r.Authority != "rsa" {
			return errors.New("explicit fixed CA authority required")
		}
	} else if r.Authority != "" {
		return errors.New("irrelevant CA authority refused")
	}
	if r.requiresCASelection() {
		if !hashPattern.MatchString(r.SelectionSHA256) || r.IssuanceSequence < 1 || r.IssuanceSequence >= r.Sequence {
			return errors.New("independent earlier issued-result selection required")
		}
	} else if r.SelectionSHA256 != "" || r.IssuanceSequence != 0 {
		return errors.New("irrelevant CA selector refused")
	}
	return nil
}
func DecodeRequest(raw []byte) (Request, error) {
	var r Request
	if len(raw) > MaxRequestBytes || decodeCanonicalJSON(raw, &r) != nil {
		return r, errors.New("bounded strict scenario request required")
	}
	if e := r.Validate(); e != nil {
		return r, e
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return r, errors.New("scenario object required")
	}
	allowed := map[string]bool{}
	if bodyKind(r.Action) == "ledger" {
		allowed["node"] = true
		allowed["sessions"] = true
	}
	if bodyKind(r.Action) == "lifecycle" {
		allowed["node"] = true
	}
	if bodyKind(r.Action) == "ca" {
		allowed["authority"] = true
	}
	if r.requiresCASelection() {
		allowed["selection_sha256"] = true
		allowed["issuance_sequence"] = true
	}
	for _, key := range []string{"node", "sessions", "authority", "selection_sha256", "issuance_sequence"} {
		if _, present := fields[key]; present && !allowed[key] {
			return r, errors.New("irrelevant selector presence refused")
		}
	}
	return r, nil
}
func (r Request) RecordName() (string, error) {
	if e := r.Validate(); e != nil {
		return "", e
	}
	return fmt.Sprintf("%s-%d.json", r.AttemptID, r.Sequence), nil
}
func DecodeStage(raw []byte) (Stage, error) {
	var s Stage
	if len(raw) > 1024 || decodeCanonicalJSON(raw, &s) != nil {
		return s, errors.New("strict fixed stage request required")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return s, errors.New("stage object required")
	}
	if s.Stage == "scenario-operation" {
		if len(fields) != 4 || !attemptPattern.MatchString(s.AttemptID) || s.Sequence < 1 || s.Sequence > MaxSequence || !hashPattern.MatchString(s.RequestSHA256) {
			return s, errors.New("independently pinned scenario stage required")
		}
		return s, nil
	}
	switch s.Stage {
	case "keys", "prepare", "cutover", "deactivate", "proofs", "resume", "observe", "recover", "verify-cloud":
		if len(fields) == 1 {
			return s, nil
		}
	}
	return s, errors.New("closed stage with no irrelevant fields required")
}
