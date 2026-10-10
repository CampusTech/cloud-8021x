package main

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

func validateRunCase(caseName, phase string) error {
	if !outerCase(caseName) {
		return errors.New("closed scenario case required")
	}
	if caseName == "ca-ec-continuity" || caseName == "ca-rsa-continuity" {
		if phase != "original" && phase != "adopted" && phase != "passive" {
			return errors.New("explicit fixed CA phase required")
		}
	} else if phase != "" {
		return errors.New("CA phase outside CA case")
	}
	return nil
}

// This path only decodes caller-supplied immutable stdin bytes. It never reads
// installed state, creates an attempt, starts a process or opens a socket.
func dryRunScenario(caseName, pin, phase string, raw []byte) ([]byte, error) {
	if e := validateRunCase(caseName, phase); e != nil {
		return nil, e
	}
	p, e := decodeNASPlan(raw, pin)
	if e != nil || p.Scenario.Case != caseName {
		return nil, errors.New("exact immutable dry-run case plan required")
	}
	actions := []string{}
	if p.Scenario.Scenario == "ca-continuity" {
		switch phase {
		case "original":
			actions = []string{"nas-ca-original", "read-ca-issued"}
		case "adopted":
			actions = []string{"read-ca-issued", "nas-ca-adopted", "read-ca-issued"}
		case "passive":
			actions = []string{"read-ca-issued", "read-ca-issued", "nas-ca-passive", "read-ca-issued", "read-ca-issued"}
		}
	} else {
		requests, e := outerAccountingRequests(p.Scenario, "task11-"+strings.Repeat("0", 32), pin)
		if e != nil {
			return nil, e
		}
		for _, r := range requests {
			actions = append(actions, r.Action)
		}
	}
	body := struct {
		Schema          int      `json:"schema"`
		Kind            string   `json:"kind"`
		Case            string   `json:"case"`
		PlanSHA256      string   `json:"plan_sha256"`
		CollectionEpoch string   `json:"collection_epoch"`
		Phase           string   `json:"phase,omitempty"`
		Actions         []string `json:"actions"`
	}{1, "scenario-plan", caseName, pin, p.Scenario.CollectionEpoch.Format(time.RFC3339), phase, actions}
	out, e := json.Marshal(body)
	if e != nil || len(out) > 4096 {
		return nil, errors.New("bounded public dry-run projection unavailable")
	}
	return out, nil
}
