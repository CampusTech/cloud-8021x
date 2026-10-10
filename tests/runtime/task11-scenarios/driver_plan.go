package main

import (
	"errors"

	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

// Requests use the controller's sole exported strict data envelope. This pure
// planner performs no service call and does not copy the controller FSM.
func accountingRequests(p scenarioPlan, attempt, planPin string) ([]scenariocontract.Request, error) {
	if e := validatePlan(p); e != nil {
		return nil, e
	}
	if !shaPattern.MatchString(planPin) {
		return nil, errors.New("independently pinned immutable plan required")
	}
	actions := []string{"probe-active-pair", "read-accounting"}
	switch p.Scenario {
	case "native-accounting":
		actions = []string{"probe-active-pair", "probe-owned-cleanup", "read-accounting", "nas-native", "read-accounting"}
	case "ongoing-baseline":
		actions = append(actions, "nas-ongoing", "read-accounting")
	case "duplicate-pair":
		actions = append(actions, "nas-duplicates", "read-accounting")
	case "ha-primary":
		if p.Node != "green-secondary" {
			return nil, errors.New("HA traffic must target the surviving secondary")
		}
		actions = append(actions, "stop-green-primary", "nas-native", "start-green-primary", "probe-active-pair", "read-accounting", "reboot-green-primary", "probe-active-pair")
	case "postgres-outage":
		actions = append(actions, "stop-postgres", "nas-outage", "start-postgres", "read-accounting", "probe-active-pair")
	case "business-outage":
		actions = append(actions, "intake-unavailable", "nas-native", "read-accounting", "reboot-green-primary", "probe-active-pair", "read-accounting", "intake-ready", "read-accounting")
	default:
		return nil, errors.New("closed accounting scenario required")
	}
	result := make([]scenariocontract.Request, 0, len(actions))
	for i, action := range actions {
		r := scenariocontract.Request{Schema: 1, AttemptID: attempt, Sequence: i + 1, Action: action, Pins: scenariocontract.Pins{PlanSHA256: planPin, PlatformSHA256: p.PlatformSHA256, EnrollmentSHA256: p.EnrollmentSHA256, ApplicationSHA256: p.ApplicationSHA256, ScenarioSHA256: p.SelfSHA256}}
		switch action {
		case "read-accounting":
			r.Node = p.Node
			r.Sessions = []string{p.Session}
		case "stop-green-primary", "start-green-primary", "reboot-green-primary":
			r.Node = "green-primary"
		}
		if e := r.Validate(); e != nil {
			return nil, e
		}
		result = append(result, r)
	}
	return result, nil
}
