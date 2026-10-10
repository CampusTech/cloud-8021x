package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

func TestOuterAccountingDriverRunsMeasuredBeforeNASAfterAndRefusesEvidenceGaps(t *testing.T) {
	p, n, l := pureMeasuredLedger(t)
	a := outerAttempt{Schema: 1, Case: p.Scenario.Case, AttemptID: "task11-" + strings.Repeat("1", 32), PlanSHA256: strings.Repeat("9", 64)}
	for _, fault := range []string{"", "first-read", "native", "ledger", "transport", "cleanup-missing", "cleanup-populated", "cleanup-retirement", "cleanup-pin", "cleanup-body"} {
		actions := []string{}
		reads := 0
		invoke := func(_ context.Context, r sc.Request) (retiredOperation, error) {
			actions = append(actions, r.Action)
			op := retiredOperation{request: r}
			op.result = sc.Result{Pins: r.Pins}
			switch r.Action {
			case "probe-active-pair":
				op.result.Probe = &sc.PairObservation{Nodes: map[string]sc.NodeObservation{p.Scenario.Node: {Epoch: p.Scenario.CollectionEpoch, ConfigSHA256: l.ConfigSHA256}}}
			case "probe-owned-cleanup":
				rawRequest, _ := json.Marshal(r)
				now := p.Scenario.CollectionEpoch.Add(time.Hour)
				cases := []sc.CleanupCase{}
				for _, kind := range []string{"deadline", "helper-death"} {
					cases = append(cases, sc.CleanupCase{Kind: kind, SentinelObservedAlive: true, SentinelRetired: true, Processes: []sc.ProcessObservation{{HostPID: 12, StartTicks: 23, ControlGroup: "/system.slice/task11-acceptance.service/operation-test", Retired: true}, {HostPID: 13, StartTicks: 24, ControlGroup: "/system.slice/task11-acceptance.service/operation-test", Retired: true}}})
				}
				op.result = sc.Result{Schema: 1, Kind: "scenario-operation", AttemptID: r.AttemptID, Sequence: r.Sequence, Action: r.Action, Pins: r.Pins, RequestSHA256: digestBytes(rawRequest), StartedAt: now, FinishedAt: now.Add(time.Second), Retired: true, Cleanup: &sc.CleanupObservation{Cases: cases}}
				switch fault {
				case "cleanup-missing":
					op.result.Cleanup = nil
				case "cleanup-populated":
					op.result.Cleanup.Cases[0].Populated = true
				case "cleanup-retirement":
					op.result.Cleanup.Cases[1].Processes[0].Retired = false
				case "cleanup-pin":
					op.result.RequestSHA256 = strings.Repeat("0", 64)
				case "cleanup-body":
					op.result.Ledger = &l
				}
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
			if e != nil || len(ops) != 5 || strings.Join(actions, ",") != "probe-active-pair,probe-owned-cleanup,read-accounting,nas-native,read-accounting" {
				t.Fatal("real measured sequence absent", e)
			}
		} else if e == nil {
			t.Fatal("driver accepted actual evidence gap", fault)
		}
		if strings.HasPrefix(fault, "cleanup-") && len(actions) != 2 {
			t.Fatal("traffic continued after missing/foreign cleanup evidence")
		}
		if fault == "first-read" && len(actions) != 3 {
			t.Fatal("traffic sent into existing session")
		}
		if fault == "transport" && len(actions) != 4 {
			t.Fatal("uncertain mutation automatically retried")
		}
	}
}
