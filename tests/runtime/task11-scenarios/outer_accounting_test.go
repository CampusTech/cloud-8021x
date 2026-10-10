package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

func TestOuterAccountingDriverRunsMeasuredBeforeNASAfterAndRefusesEvidenceGaps(t *testing.T) {
	p, n, l := pureMeasuredLedger(t)
	a := outerAttempt{Schema: 1, Case: p.Scenario.Case, AttemptID: "task11-" + strings.Repeat("1", 32), PlanSHA256: strings.Repeat("9", 64)}
	for _, fault := range []string{"", "first-read", "native", "ledger", "transport"} {
		actions := []string{}
		reads := 0
		invoke := func(_ context.Context, r sc.Request) (retiredOperation, error) {
			actions = append(actions, r.Action)
			op := retiredOperation{request: r}
			op.result = sc.Result{Pins: r.Pins}
			switch r.Action {
			case "probe-active-pair":
				op.result.Probe = &sc.PairObservation{Nodes: map[string]sc.NodeObservation{p.Scenario.Node: {Epoch: p.Scenario.CollectionEpoch, ConfigSHA256: l.ConfigSHA256}}}
			case "read-accounting":
				reads++
				value := l
				if reads == 1 {
					value.Sessions = nil
					value.Observations = nil
					value.Intervals = nil
					value.Outbox = nil
				}
				if fault == "first-read" && reads == 1 {
					value = l
				}
				if fault == "ledger" && reads > 1 {
					value.Epoch = value.Epoch.AddDate(0, 0, 1)
				}
				op.result.Ledger = &value
			case "nas-native":
				value := n
				if fault == "native" {
					value.EAP.Accepted = false
				}
				op.result.NAS = &value
			}
			if fault == "transport" && r.Action == "nas-native" {
				return op, errors.New("uncertain")
			}
			op.raw, _ = json.Marshal(op.result)
			return op, nil
		}
		ops, e := executeAccountingActions(context.Background(), p, a, invoke)
		if fault == "" {
			if e != nil || len(ops) != 4 || strings.Join(actions, ",") != "probe-active-pair,read-accounting,nas-native,read-accounting" {
				t.Fatal("real measured sequence absent", e)
			}
		} else if e == nil {
			t.Fatal("driver accepted actual evidence gap", fault)
		}
		if fault == "first-read" && len(actions) != 2 {
			t.Fatal("traffic sent into existing session")
		}
		if fault == "transport" && len(actions) != 3 {
			t.Fatal("uncertain mutation automatically retried")
		}
	}
}
