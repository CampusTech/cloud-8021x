package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
	"golang.org/x/sys/unix"
)

type retiredOperation struct {
	request sc.Request
	result  sc.Result
	raw     []byte
}

func planPins(p nasPrivatePlan, pin string) sc.Pins {
	return sc.Pins{PlanSHA256: pin, PlatformSHA256: p.Scenario.PlatformSHA256, EnrollmentSHA256: p.Scenario.EnrollmentSHA256, ApplicationSHA256: p.Scenario.ApplicationSHA256, ScenarioSHA256: p.Scenario.SelfSHA256}
}
func retiredHistory(s *outerStore, p nasPrivatePlan, a outerAttempt) ([]retiredOperation, error) {
	for _, dir := range []string{"requests", "results", "failures", "claims", "ca-selections"} {
		if e := s.checkRecordDirectory(dir, a.AttemptID+"-1.json"); e != nil {
			return nil, e
		}
	}
	history := []retiredOperation{}
	gap := false
	var ended time.Time
	for sequence := 1; sequence <= sc.MaxSequence; sequence++ {
		name := fmt.Sprintf("%s-%d.json", a.AttemptID, sequence)
		raw, e := s.read("requests", name, sc.MaxRequestBytes)
		if errors.Is(e, unix.ENOENT) {
			gap = true
			for _, dir := range []string{"results", "failures", "claims", "ca-selections"} {
				orphan, e := s.read(dir, name, sc.MaxResultBytes)
				clear(orphan)
				if e == nil || !errors.Is(e, unix.ENOENT) {
					return nil, errors.New("orphan or unsafe scenario history")
				}
			}
			continue
		}
		if e != nil || gap {
			return nil, errors.New("incomplete protected request history")
		}
		request, e := sc.DecodeRequest(raw)
		if e != nil || request.AttemptID != a.AttemptID || request.Sequence != sequence || !reflect.DeepEqual(request.Pins, planPins(p, a.PlanSHA256)) || validateCaseRequest(p.Scenario, request) != nil {
			return nil, errors.New("retained request identity or case changed")
		}
		failure, e := s.read("failures", name, 4096)
		clear(failure)
		if e == nil || !errors.Is(e, unix.ENOENT) {
			return nil, errors.New("retained failed operation requires reconciliation")
		}
		resultRaw, e := s.read("results", name, sc.MaxResultBytes)
		if e != nil {
			return nil, errors.New("retained uncertain operation requires reconciliation")
		}
		result, e := sc.DecodeResult(resultRaw, request, digestBytes(raw))
		if e != nil || (!ended.IsZero() && result.StartedAt.Before(ended)) {
			return nil, errors.New("retained result is unretired, substituted or reordered")
		}
		ended = result.FinishedAt
		history = append(history, retiredOperation{request: request, result: result, raw: resultRaw})
	}
	return history, nil
}
func publishIssuedSelection(s *outerStore, operation retiredOperation) (sc.CASelection, []byte, error) {
	selection, raw, e := issuedSelection(operation.result, operation.raw)
	if e != nil {
		return selection, nil, e
	}
	name, e := operation.request.RecordName()
	if e != nil {
		return selection, nil, e
	}
	prior, e := s.read("ca-selections", name, 2048)
	if e == nil {
		existing, e := sc.DecodeCASelection(prior)
		if e != nil || existing != selection {
			return selection, nil, errors.New("retained issued selection differs")
		}
		return selection, prior, nil
	}
	if !errors.Is(e, unix.ENOENT) {
		return selection, nil, e
	}
	if e = s.create("ca-selections", name, raw); e != nil {
		return selection, nil, e
	}
	return selection, raw, nil
}
func existingCAOriginal(history []retiredOperation, authority string) (retiredOperation, *sc.CAObservation, error) {
	var original retiredOperation
	var observed *sc.CAObservation
	for _, op := range history {
		if op.result.CA != nil && op.result.CA.Phase == "original" {
			if original.raw != nil || op.result.CA.Authority != authority {
				return original, nil, errors.New("ambiguous original CA history")
			}
			original = op
		}
		if op.result.CAIssued != nil && original.raw != nil && op.result.CAIssued.IssuanceResultSHA256 == digestBytes(original.raw) {
			v := *op.result.CAIssued
			if observed == nil {
				observed = &v
			} else if preserveCAStored(*observed, v) != nil {
				return original, nil, errors.New("original issued row changed")
			}
		}
	}
	if original.raw == nil || observed == nil {
		return original, nil, errors.New("genuine original issuance and DB observation required before phase handoff")
	}
	return original, observed, nil
}
func phaseNotAlreadyAttempted(history []retiredOperation, phase string) error {
	latest := ""
	for _, op := range history {
		if op.result.CA != nil {
			if op.result.CA.Phase == phase {
				return errors.New("retained CA phase refuses automatic rerun")
			}
			latest = op.result.CA.Phase
		}
	}
	prior := map[string]string{"adopted": "original", "passive": "adopted"}[phase]
	if latest != prior {
		return errors.New("prior retired CA phase required")
	}
	if len(history) == 0 || history[len(history)-1].result.CAIssued == nil {
		return errors.New("phase requires completed prior issued row observation")
	}
	return nil
}

// No history status marker is consulted; actual protected request/result bytes
// and controller retirement are the only prior-operation evidence.
func marshalPublicDriverResult(caseName string, a outerAttempt, ops []retiredOperation) ([]byte, error) {
	type coordinate struct {
		Sequence     int    `json:"sequence"`
		Action       string `json:"action"`
		ResultSHA256 string `json:"result_sha256"`
	}
	body := struct {
		Schema     int          `json:"schema"`
		Case       string       `json:"case"`
		AttemptID  string       `json:"attempt_id"`
		PlanSHA256 string       `json:"plan_sha256"`
		Operations []coordinate `json:"operations"`
		Remaining  []string     `json:"remaining"`
	}{Schema: 1, Case: caseName, AttemptID: a.AttemptID, PlanSHA256: a.PlanSHA256, Remaining: []string{"installed independent full acceptance", "controller passive and boot gates", "deactivated actual cloud intake reconciliation"}}
	for _, op := range ops {
		body.Operations = append(body.Operations, coordinate{op.request.Sequence, op.request.Action, digestBytes(op.raw)})
	}
	raw, e := json.Marshal(body)
	if e != nil || len(raw) > 8192 {
		return nil, errors.New("bounded measured operation coordinates unavailable")
	}
	if strings.Contains(string(raw), "class-key") {
		return nil, errors.New("private driver output refused")
	}
	return raw, nil
}
