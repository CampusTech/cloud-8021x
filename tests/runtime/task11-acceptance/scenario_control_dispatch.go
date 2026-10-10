package main

import (
	"context"
	"io"
	"slices"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

// Use the private admitted bytes. Caller-visible claim copies are observations,
// and cannot select a different operation or replace the private handoff.
func scenarioControlBody(ctx context.Context, e enrollment, claim *scenarioClaim, result *sc.Result, call func(context.Context, enrollment, []byte) (scenarioControlObservation, error)) error {
	if ctx.Err() != nil || claim == nil || result == nil || call == nil || result.Action != claim.request.Action || adoption.Digest(claim.raw) != claim.sha || result.Probe != nil || result.Lifecycle != nil || result.Gate != nil || result.Cleanup != nil || result.NAS != nil || result.CA != nil || result.CAIssued != nil || result.Ledger != nil {
		return errScenarioControl
	}
	action := claim.request.Action
	if !slices.Contains([]string{"probe-active-pair", "stop-green-primary", "start-green-primary", "reboot-green-primary", "stop-postgres", "start-postgres", "intake-unavailable", "intake-ready", "probe-owned-cleanup"}, action) {
		return errScenarioControl
	}
	observed, err := call(ctx, e, claim.raw)
	if err != nil || ctx.Err() != nil {
		return errScenarioControl
	}
	count := 0
	for _, present := range []bool{observed.Probe != nil, observed.Lifecycle != nil, observed.Gate != nil, observed.Cleanup != nil} {
		if present {
			count++
		}
	}
	if count != 1 {
		return errScenarioControl
	}
	switch action {
	case "probe-active-pair":
		if observed.Probe == nil {
			return errScenarioControl
		}
		result.Probe = observed.Probe
	case "stop-green-primary", "start-green-primary", "reboot-green-primary":
		if observed.Lifecycle == nil {
			return errScenarioControl
		}
		result.Lifecycle = observed.Lifecycle
	case "stop-postgres", "start-postgres", "intake-unavailable", "intake-ready":
		if observed.Gate == nil {
			return errScenarioControl
		}
		result.Gate = observed.Gate
	case "probe-owned-cleanup":
		if observed.Cleanup == nil {
			return errScenarioControl
		}
		result.Cleanup = observed.Cleanup
	}
	return nil
}

// A probe has one closed public selector; all private authority travels through
// the same untouched input/output streams as the existing node transport.
func dispatchScenarioProbe(ctx context.Context, args []string, in io.Reader, out io.Writer, call func(context.Context, io.Reader, io.Writer) error) (bool, error) {
	if len(args) == 0 {
		return true, errScenarioControl
	}
	if args[0] != "scenario-probe" {
		return false, nil
	}
	if len(args) != 1 || call == nil || ctx.Err() != nil {
		return true, errScenarioControl
	}
	return true, call(ctx, in, out)
}
