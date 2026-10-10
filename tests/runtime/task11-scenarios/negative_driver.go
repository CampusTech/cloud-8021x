package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

// The native runner authenticates Access-Reject/EAP-Failure and waits for an
// actual nonzero child exit. The controller supplies independently retired raw
// results; an absent/timeout/default body can never replace that observation.
func executeRejectedActions(ctx context.Context, p nasPrivatePlan, a outerAttempt, invoke measuredInvoker) ([]retiredOperation, error) {
	requests, e := accountingRequests(p.Scenario, a.AttemptID, a.PlanSHA256)
	if e != nil || invoke == nil || ctx == nil || ctx.Err() != nil {
		return nil, errors.New("fixed measured rejection route required")
	}
	operations := []retiredOperation{}
	configPin := ""
	reads := 0
	rejected := false
	for _, request := range requests {
		if ctx.Err() != nil {
			return nil, errors.New("rejection deadline expired")
		}
		op, e := invoke(ctx, request)
		if e != nil {
			return nil, e
		}
		rq, e := json.Marshal(request)
		if e != nil {
			return nil, e
		}
		result, e := sc.DecodeResult(op.raw, request, digestBytes(rq))
		if e != nil {
			return nil, errors.New("bound retired rejection observation differs")
		}
		switch request.Action {
		case "probe-active-pair":
			if result.Probe == nil {
				return nil, errors.New("actual active pair missing")
			}
			node, ok := result.Probe.Nodes[p.Scenario.Node]
			if !ok || !node.Epoch.Equal(p.Scenario.CollectionEpoch) || !shaPattern.MatchString(node.ConfigSHA256) {
				return nil, errors.New("actual rejection node binding differs")
			}
			configPin = node.ConfigSHA256
		case "nas-native", "read-accounting":
			if request.Action == "nas-native" {
				n := result.NAS
				if n == nil || !n.EAP.Rejected || n.EAP.Accepted || n.EAP.ResponseCode != 3 || !shaPattern.MatchString(n.EAP.ResponseAuthenticatorSHA256) || n.EAP.TunnelType != 0 || n.EAP.TunnelMediumType != 0 || n.EAP.VLAN != 0 || n.Peer != p.Scenario.Target || n.Session != p.Scenario.Session || n.Station != p.Station || n.ClassSHA256 != "" || !reflect.DeepEqual(n.Attribution, binding.Attribution{}) || len(n.Expected.EventIDs)+len(n.Expected.UsageIDs) != 0 || n.Expected.UploadBytes != 0 || n.Expected.DownloadBytes != 0 || n.Expected.Seconds != 0 || len(n.Packets) != 0 {
					return nil, errors.New("genuine assignment-free rejection required")
				}
				rejected = true
			} else {
				l := result.Ledger
				if l == nil || configPin == "" || l.ConfigSHA256 != configPin || !l.Epoch.Equal(p.Scenario.CollectionEpoch) || l.Deployment != "task11-green" || l.Database != "cloud8021x_task11_green" || !l.ReadOnly || l.Isolation != "repeatable-read" || len(l.Sessions)+len(l.Observations)+len(l.Intervals)+len(l.Outbox) != 0 {
					return nil, errors.New("fresh before/after rejection ledger must remain empty")
				}
				reads++
			}
		default:
			return nil, errors.New("action outside fixed rejection graph")
		}
		operations = append(operations, op)
	}
	if !rejected || reads != 2 || len(operations) != 4 {
		return nil, errors.New("complete measured rejection graph required")
	}
	return operations, nil
}
