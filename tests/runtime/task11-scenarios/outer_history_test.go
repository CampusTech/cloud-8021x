package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

func TestOuterHistoryRefusesAnyUncertainUnretiredOrUnknownRecord(t *testing.T) {
	f := purePriorNASInput(t)
	p, e := decodeNASPlan(f.input.PlanBytes, f.input.PlanSHA256)
	if e != nil {
		t.Fatal(e)
	}
	var result sc.Result
	_ = json.Unmarshal(f.input.Prior.ResultBytes, &result)
	request := sc.Request{Schema: 1, AttemptID: result.AttemptID, Sequence: 1, Action: "nas-ca-original", Authority: "rsa", Pins: result.Pins}
	raw, _ := json.Marshal(request)
	raw = append(raw, '\n')
	name, _ := request.RecordName()
	a := outerAttempt{Schema: 1, Case: p.Scenario.Case, AttemptID: result.AttemptID, PlanSHA256: f.input.PlanSHA256}
	for _, fault := range []string{"", "missing-result", "unretired", "unknown-record", "orphan", "changed-request"} {
		t.Run(fault, func(t *testing.T) {
			root, _ := filepath.EvalSymlinks(t.TempDir())
			_ = os.Chmod(root, 0700)
			s, e := openOuterStore(root, os.Getuid())
			if e != nil {
				t.Fatal(e)
			}
			defer s.close()
			requestRaw := append([]byte(nil), raw...)
			if fault == "changed-request" {
				requestRaw = append(requestRaw, ' ')
			}
			if e = s.create("requests", name, requestRaw); e != nil {
				t.Fatal(e)
			}
			value := result
			if fault == "unretired" {
				value.Retired = false
			}
			valueRaw, _ := json.Marshal(value)
			if fault != "missing-result" {
				if e = s.create("results", name, valueRaw); e != nil {
					t.Fatal(e)
				}
			}
			if fault == "unknown-record" {
				if e = os.WriteFile(filepath.Join(root, "requests", result.AttemptID+"-25.json"), []byte("{}"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if fault == "orphan" {
				future := request
				future.Sequence = 2
				futureName, _ := future.RecordName()
				if e = s.create("results", futureName, valueRaw); e != nil {
					t.Fatal(e)
				}
			}
			history, e := retiredHistory(s, p, a)
			if fault == "" {
				if e != nil || len(history) != 1 {
					t.Fatal("actual retired preserved history refused", e)
				}
			} else if e == nil {
				t.Fatal("unknown/uncertain protected history accepted", fault)
			}
		})
	}
}
