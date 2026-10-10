package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"time"

	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

type measuredInvoker func(context.Context, sc.Request) (retiredOperation, error)

func boundedDriverPause(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return errors.New("driver deadline leaves retained irreversible history")
	case <-timer.C:
		return nil
	}
}
func selectedLedgerIncomplete(l sc.LedgerObservation, n sc.NASResult) bool {
	if len(l.Observations) > len(n.Expected.EventIDs) || len(l.Intervals) > len(n.Expected.UsageIDs) || len(l.Outbox) > len(n.Expected.EventIDs)+len(n.Expected.UsageIDs) {
		return false
	}
	for _, v := range l.Observations {
		if !slices.Contains(n.Expected.EventIDs, v.EventID) {
			return false
		}
	}
	for _, v := range l.Intervals {
		if !slices.Contains(n.Expected.UsageIDs, v.UsageID) {
			return false
		}
	}
	return len(l.Observations) < len(n.Expected.EventIDs) || len(l.Intervals) < len(n.Expected.UsageIDs) || len(l.Outbox) < len(n.Expected.EventIDs)+len(n.Expected.UsageIDs)
}
func measuredNodeContinuity(before, after sc.NodeObservation, newBoot bool) error {
	if before.Machine != after.Machine || before.Root != after.Root || before.MachineID != after.MachineID || before.ConfigSHA256 != after.ConfigSHA256 || before.ApplicationSHA256 != after.ApplicationSHA256 || before.Deployment != after.Deployment || !before.Epoch.Equal(after.Epoch) || before.Collector.BackingFile != after.Collector.BackingFile || before.Collector.FileDevice != after.Collector.FileDevice || before.Collector.FileInode != after.Collector.FileInode || before.Collector.ByteSize != after.Collector.ByteSize || before.Collector.Filesystem != after.Collector.Filesystem {
		return errors.New("actual preserved node and collector identity changed")
	}
	if newBoot {
		if before.BootID == after.BootID || (before.Leader == after.Leader && before.LeaderStartTicks == after.LeaderStartTicks) {
			return errors.New("genuine new boot and retired old leader required")
		}
	} else if before.BootID != after.BootID || before.Leader != after.Leader || before.LeaderStartTicks != after.LeaderStartTicks || !reflect.DeepEqual(before.Namespaces, after.Namespaces) {
		return errors.New("uncontrolled node identity change")
	}
	return nil
}
func executeAccountingActions(ctx context.Context, p nasPrivatePlan, a outerAttempt, invoke measuredInvoker) ([]retiredOperation, error) {
	if p.Scenario.Case == "eap-unenrolled" {
		return executeRejectedActions(ctx, p, a, invoke)
	}
	planned, e := outerAccountingRequests(p.Scenario, a.AttemptID, a.PlanSHA256)
	if e != nil || invoke == nil {
		return nil, errors.New("fixed measured accounting route required")
	}
	operations := []retiredOperation{}
	sequence := 0
	var nas *sc.NASResult
	var retained *sc.LedgerObservation
	var outageAt time.Time
	configPin := ""
	nodes := map[string]sc.NodeObservation{}
	call := func(r sc.Request) (retiredOperation, error) {
		sequence++
		if sequence > sc.MaxSequence {
			return retiredOperation{}, errors.New("bounded read-only convergence exhausted")
		}
		r.Sequence = sequence
		operation, err := invoke(ctx, r)
		if err != nil {
			return operation, err
		}
		operations = append(operations, operation)
		return operation, nil
	}
	for _, request := range planned {
		if (request.Action == "start-postgres" || request.Action == "intake-ready") && !outageAt.IsZero() {
			if e = boundedDriverPause(ctx, time.Until(outageAt.Add(time.Duration(p.Scenario.OutageSeconds)*time.Second))); e != nil {
				return nil, e
			}
		}
		op, e := call(request)
		if e != nil {
			return nil, e
		}
		result := op.result
		switch request.Action {
		case "probe-active-pair":
			if result.Probe == nil {
				return nil, errors.New("actual active pair observation missing")
			}
			target, ok := result.Probe.Nodes[p.Scenario.Node]
			if !ok || !target.Epoch.Equal(p.Scenario.CollectionEpoch) || !shaPattern.MatchString(target.ConfigSHA256) {
				return nil, errors.New("actual configured node epoch differs")
			}
			configPin = target.ConfigSHA256
			for name, after := range result.Probe.Nodes {
				if before, exists := nodes[name]; exists && measuredNodeContinuity(before, after, false) != nil {
					return nil, errors.New("uncontrolled active pair change")
				}
				nodes[name] = after
			}
		case "probe-owned-cleanup":
			// Reuse the sole strict body/retirement decoder with the exact
			// request bytes published by submitOperation before any traffic.
			rawRequest, err := json.Marshal(request)
			if err != nil || result.Cleanup == nil {
				return nil, errors.New("actual owned cleanup observation missing")
			}
			if _, err = sc.DecodeResult(op.raw, request, digestBytes(rawRequest)); err != nil {
				return nil, errors.New("bound retired cleanup evidence differs")
			}
		case "stop-green-primary", "start-green-primary", "reboot-green-primary":
			lifecycle := result.Lifecycle
			if lifecycle == nil {
				return nil, errors.New("actual owned lifecycle evidence missing")
			}
			if lifecycle.Before != nil {
				if before, ok := nodes["green-primary"]; ok && measuredNodeContinuity(before, *lifecycle.Before, false) != nil {
					return nil, errors.New("lifecycle before identity differs")
				}
				nodes["green-primary"] = *lifecycle.Before
			}
			if request.Action != "stop-green-primary" {
				before, ok := nodes["green-primary"]
				if !ok || lifecycle.After == nil || !lifecycle.OldLeaderRetired || measuredNodeContinuity(before, *lifecycle.After, true) != nil {
					return nil, errors.New("new boot with preserved collector and retired old leader required")
				}
				nodes["green-primary"] = *lifecycle.After
			}
		case "stop-postgres", "start-postgres", "intake-unavailable", "intake-ready":
			if result.Gate == nil {
				return nil, errors.New("actual fixed outage gate missing")
			}
			if request.Action == "stop-postgres" || request.Action == "intake-unavailable" {
				outageAt = result.Gate.ObservedAt
			}
		case "nas-native", "nas-ongoing", "nas-duplicates", "nas-outage":
			if result.NAS == nil || nas != nil || !result.NAS.EAP.Accepted || result.NAS.EAP.Rejected {
				return nil, errors.New("genuine accepted EAP and one immutable traffic operation required")
			}
			nas = result.NAS
			if p.Scenario.Scenario == "postgres-outage" {
				for _, packet := range nas.Packets {
					if packet.ACK {
						return nil, errors.New("database outage unexpectedly acknowledged")
					}
				}
			}
		case "read-accounting":
			ledger := result.Ledger
			if ledger == nil || ledger.ConfigSHA256 != configPin || !ledger.Epoch.Equal(p.Scenario.CollectionEpoch) {
				return nil, errors.New("fresh selected ledger binding differs")
			}
			if nas == nil {
				if len(ledger.Sessions) != 0 || len(ledger.Observations) != 0 || len(ledger.Intervals) != 0 || len(ledger.Outbox) != 0 {
					return nil, errors.New("independent new session already exists before traffic")
				}
				continue
			}
			for polls := 0; selectedLedgerIncomplete(*ledger, *nas); polls++ {
				if polls >= 6 {
					return nil, errors.New("actual asynchronous ledger did not converge")
				}
				if e = boundedDriverPause(ctx, time.Second); e != nil {
					return nil, e
				}
				next, e := call(request)
				if e != nil || next.result.Ledger == nil {
					return nil, errors.New("fresh read-only convergence observation unavailable")
				}
				ledger = next.result.Ledger
			}
			if e = reconcileNativeLedger(p, *nas, *ledger); e != nil {
				return nil, e
			}
			if ledger.ConfigSHA256 != configPin {
				return nil, errors.New("selected ledger config changed")
			}
			if retained != nil {
				if e = preserveLedgerWork(*retained, *ledger); e != nil {
					return nil, e
				}
			} else {
				copy := *ledger
				retained = &copy
			}
			if p.Scenario.Scenario == "business-outage" && request.Sequence < len(planned) {
				for _, work := range ledger.Outbox {
					if work.State == "succeeded" {
						return nil, errors.New("business work delivered during independently unavailable intake")
					}
				}
			}
		}
	}
	if nas == nil || retained == nil {
		return nil, errors.New("genuine native traffic and complete selected ledger required")
	}
	return operations, nil
}

func outerAccountingRequests(p scenarioPlan, attempt, pin string) ([]sc.Request, error) {
	requests, e := accountingRequests(p, attempt, pin)
	if e != nil {
		return nil, e
	}
	if p.Scenario == "ha-primary" {
		r := requests[1]
		r.Sequence = len(requests) + 1
		requests = append(requests, r)
	}
	return requests, nil
}
