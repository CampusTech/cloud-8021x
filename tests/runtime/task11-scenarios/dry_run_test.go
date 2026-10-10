package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRunDryRunValidatesExactPrivatePlanWithoutRuntimeAndEmitsOnlyClosedActions(t *testing.T) {
	p := pureNASPlan()
	raw, _ := json.Marshal(p)
	pin := digestBytes(raw)
	var out bytes.Buffer
	cmd := newScenarioCommand(bytes.NewReader(raw), &out)
	cmd.SetArgs([]string{"run", "native-accounting", "--plan-sha256", pin, "--dry-run", "--debug"})
	if e := cmd.Execute(); e != nil {
		t.Fatal("pure dry-run unavailable", e)
	}
	var projected struct {
		Schema          int      `json:"schema"`
		Kind            string   `json:"kind"`
		Case            string   `json:"case"`
		PlanSHA256      string   `json:"plan_sha256"`
		CollectionEpoch string   `json:"collection_epoch"`
		Phase           string   `json:"phase,omitempty"`
		Actions         []string `json:"actions"`
	}
	if e := strictJSON(out.Bytes(), 4096, &projected); e != nil {
		t.Fatal("bounded public plan projection absent", e)
	}
	if projected.Kind != "scenario-plan" || projected.Schema != 1 || projected.Case != p.Scenario.Case || projected.PlanSHA256 != pin || strings.Join(projected.Actions, ",") != "probe-active-pair,probe-owned-cleanup,read-accounting,nas-native,read-accounting" {
		t.Fatal("dry-run inferred state or lost closed actions")
	}
	for _, name := range []string{"radius-secret", "class-key", "materials", "client.key", "attempt_id", "retired", "pass"} {
		if bytes.Contains(out.Bytes(), []byte(name)) {
			t.Fatal("private material or fabricated runtime fact in dry-run", name)
		}
	}
	for _, args := range [][]string{{"run", "native-accounting", "--plan-sha256", strings.Repeat("a", 64), "--dry-run"}, {"run", "ca-ec-continuity", "--plan-sha256", pin, "--dry-run"}, {"run", "native-accounting", "--plan-sha256", pin, "--dry-run", "--endpoint", "https://outside"}} {
		var output bytes.Buffer
		command := newScenarioCommand(bytes.NewReader(raw), &output)
		command.SetArgs(args)
		if command.Execute() == nil || output.Len() != 0 {
			t.Fatal("unknown/unbound dry-run accepted")
		}
	}
}
