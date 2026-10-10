package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"golang.org/x/sys/unix"
)

type outerAttempt struct {
	Schema     int    `json:"schema"`
	Case       string `json:"case"`
	AttemptID  string `json:"attempt_id"`
	PlanSHA256 string `json:"plan_sha256"`
}

func bindOuterAttempt(s *outerStore, p nasPrivatePlan, pin, phase string, entropy io.Reader) (outerAttempt, error) {
	var a outerAttempt
	plan := p.Scenario
	if validatePlan(plan) != nil || !shaPattern.MatchString(pin) || !outerCase(plan.Case) {
		return a, errors.New("closed immutable attempt plan required")
	}
	ca := plan.Scenario == "ca-continuity"
	if ca {
		if phase != "original" && phase != "adopted" && phase != "passive" {
			return a, errors.New("explicit CA phase required")
		}
	} else if phase != "" {
		return a, errors.New("CA phase outside CA case")
	}
	name := plan.Case + ".json"
	prior, e := s.read("attempts", name, 4096)
	if e == nil {
		defer clear(prior)
		if !ca || phase == "original" {
			return a, errors.New("retained irreversible attempt refuses automatic rerun")
		}
		if strictJSON(prior, 4096, &a) != nil || a.Schema != 1 || a.Case != plan.Case || a.PlanSHA256 != pin || !outerRecordPattern.MatchString(a.AttemptID+"-1.json") {
			return a, errors.New("retained CA attempt identity differs")
		}
		return a, nil
	}
	if !errors.Is(e, unix.ENOENT) {
		return a, e
	}
	if ca && phase != "original" {
		return a, errors.New("original genuine issuance history required")
	}
	if entropy == nil {
		return a, errors.New("independent attempt entropy required")
	}
	var random [16]byte
	if _, e = io.ReadFull(entropy, random[:]); e != nil {
		return a, errors.New("attempt entropy unavailable")
	}
	a = outerAttempt{Schema: 1, Case: plan.Case, AttemptID: "task11-" + hex.EncodeToString(random[:]), PlanSHA256: pin}
	clear(random[:])
	raw, e := json.Marshal(a)
	if e != nil {
		return a, e
	}
	if e = s.create("attempts", name, raw); e != nil {
		return a, e
	}
	return a, nil
}
