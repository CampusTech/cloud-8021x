package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

func TestScenarioControlsDispatchBindsPrivateClaimAndSoleTypedBody(t *testing.T) {
	root := recordFixture(t)
	r := recordRequest(1, "probe-active-pair")
	raw := append(recordJSON(t, r), '\n')
	recordWrite(t, root, "requests", r, raw)
	store := recordOpen(t, root)
	claim, err := store.Admit(recordStage(r, raw), r.Pins)
	if err != nil {
		t.Fatal(err)
	}
	claim.RequestRaw[0] = 'x'
	claim.Request.Action = "stop-postgres"
	calls := 0
	expected := &sc.PairObservation{}
	callback := func(_ context.Context, _ enrollment, got []byte) (scenarioControlObservation, error) {
		calls++
		if !bytes.Equal(got, raw) {
			t.Fatal("caller copy replaced admitted private request")
		}
		return scenarioControlObservation{Probe: expected}, nil
	}
	result := sc.Result{Action: r.Action}
	if err := scenarioControlBody(context.Background(), enrollment{}, claim, &result, callback); err != nil || calls != 1 || result.Probe != expected || result.Retired {
		t.Fatal("actual control body not routed without inventing retirement", err, calls)
	}
	for _, kind := range []string{"other-action", "two-bodies", "wrong-body", "uncertain", "nil-callback", "canceled", "already-filled"} {
		t.Run(kind, func(t *testing.T) {
			result := sc.Result{Action: r.Action}
			fn := callback
			ctx := context.Background()
			switch kind {
			case "other-action":
				result.Action = "stop-postgres"
			case "two-bodies":
				fn = func(context.Context, enrollment, []byte) (scenarioControlObservation, error) {
					return scenarioControlObservation{Probe: expected, Gate: &sc.GateObservation{}}, nil
				}
			case "wrong-body":
				fn = func(context.Context, enrollment, []byte) (scenarioControlObservation, error) {
					return scenarioControlObservation{Gate: &sc.GateObservation{}}, nil
				}
			case "uncertain":
				fn = func(context.Context, enrollment, []byte) (scenarioControlObservation, error) {
					return scenarioControlObservation{Probe: expected}, errors.New("uncertain")
				}
			case "nil-callback":
				fn = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "already-filled":
				result.NAS = &sc.NASResult{}
			}
			before := calls
			if scenarioControlBody(ctx, enrollment{}, claim, &result, fn) == nil {
				t.Fatal("unbound or uncertain control observation accepted")
			}
			if result.Probe != nil || result.Lifecycle != nil || result.Gate != nil || result.Cleanup != nil || result.Retired {
				t.Fatal("failed control returned a successful body")
			}
			if (kind == "other-action" || kind == "nil-callback" || kind == "canceled" || kind == "already-filled") && calls != before {
				t.Fatal("invalid operation reached effect callback")
			}
		})
	}
}
func TestScenarioControlsProbePrivateNodeDispatch(t *testing.T) {
	input := []byte("opaque private input\n")
	var out bytes.Buffer
	calls := 0
	callback := func(_ context.Context, in io.Reader, w io.Writer) error {
		calls++
		got, err := io.ReadAll(in)
		if err != nil || !bytes.Equal(got, input) {
			t.Fatal("private node input changed")
		}
		_, err = w.Write([]byte("measured"))
		return err
	}
	handled, err := dispatchScenarioProbe(context.Background(), []string{"scenario-probe"}, bytes.NewReader(input), &out, callback)
	if !handled || err != nil || calls != 1 || out.String() != "measured" {
		t.Fatal("fixed node probe is not wired", handled, err)
	}
	for _, args := range [][]string{{"scenario-probe", "override"}, nil} {
		before := calls
		handled, err = dispatchScenarioProbe(context.Background(), args, bytes.NewReader(input), &out, callback)
		if !handled || err == nil || calls != before {
			t.Fatal("node override reached callback", args)
		}
	}
	before := calls
	handled, err = dispatchScenarioProbe(context.Background(), []string{"scenario-accounting"}, nil, nil, callback)
	if handled || err != nil || calls != before {
		t.Fatal("legacy node route intercepted")
	}
}
func TestScenarioControlsCleanupCommandIsClosedAndCannotDryRun(t *testing.T) {
	cmd := command()
	sub, args, err := cmd.Find([]string{"scenario-cleanup-child", "worker"})
	if err != nil || sub == cmd || sub.Name() != "scenario-cleanup-child" || !sub.Hidden {
		t.Fatal("actual owned cleanup entry missing", err)
	}
	if sub.Args(sub, args) != nil || sub.Args(sub, nil) == nil || sub.Args(sub, []string{"worker", "override"}) == nil {
		t.Fatal("cleanup args are not closed")
	}
	for _, args := range [][]string{{"--dry-run", "scenario-cleanup-child", "worker"}, {"scenario-cleanup-child", "unowned"}} {
		cmd := command()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(args)
		if cmd.Execute() == nil || out.Len() != 0 {
			t.Fatal("private cleanup entry emitted a dry-run or unowned success")
		}
	}
}
