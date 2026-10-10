package main

import (
	"errors"
	"time"
)

// This public projection contains no credentials, Class, private materials,
// selectors or success marker. The controller independently checks its pins
// against enrolled descriptors/config before any claim or operation.
type nasAdmission struct {
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

func validatePlanCase(p scenarioPlan) error {
	expected := p.Case
	switch p.Case {
	case "native-accounting", "duplicate-pair", "ha-primary", "postgres-outage", "business-outage":
	case "ongoing-interim", "ongoing-stop":
		expected = "ongoing-baseline"
		first := 3
		if p.Case == "ongoing-stop" {
			first = 2
		}
		if len(p.Events) == 0 || p.Events[0].Status != first {
			return errors.New("immutable ongoing case baseline differs")
		}
	case "ca-ec-continuity", "ca-rsa-continuity":
		expected = "ca-continuity"
	default:
		return errors.New("closed immutable case required")
	}
	if p.Scenario != expected {
		return errors.New("immutable case differs from scenario")
	}
	return nil
}
func caseAuthority(p scenarioPlan) string {
	switch p.Case {
	case "ca-ec-continuity":
		return "ec"
	case "ca-rsa-continuity":
		return "rsa"
	default:
		return ""
	}
}
func admitNASInput(raw []byte) (nasAdmission, error) {
	input, e := decodeNASInputCore(raw)
	if e != nil {
		return nasAdmission{}, e
	}
	request, p := input.Request, input.Plan
	return nasAdmission{Schema: 1, RequestSHA256: digestBytes(input.RequestBytes), PlanSHA256: request.PlanSHA256, PlatformSHA256: request.PlatformSHA256, EnrollmentSHA256: request.EnrollmentSHA256, ApplicationSHA256: request.ApplicationSHA256, ScenarioSHA256: request.ScenarioSHA256, OriginalSeedSHA256: p.OriginalSeedSHA256, CollectionEpoch: p.Scenario.CollectionEpoch, Node: p.Scenario.Node, Session: p.Scenario.Session, Case: p.Scenario.Case, Authority: caseAuthority(p.Scenario)}, nil
}
