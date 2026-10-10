package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestFixedAdmitCommandUsesPrivateStdinAndPublicBoundedProjection(t *testing.T) {
	input := pureNASInput(t)
	var out bytes.Buffer
	cmd := newScenarioCommand(bytes.NewReader(encodePureNASInput(t, input)), &out)
	cmd.SetArgs([]string{"admit"})
	if e := cmd.Execute(); e != nil {
		t.Fatal(e)
	}
	var projection nasAdmission
	if e := strictJSON(out.Bytes(), 4096, &projection); e != nil {
		t.Fatal("admit did not return its bounded actual-plan projection")
	}
	if projection.RequestSHA256 != input.RequestSHA256 || projection.PlanSHA256 != input.PlanSHA256 || projection.Case != "native-accounting" {
		t.Fatal("admit did not match exact private bytes")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(out.Bytes(), &fields) != nil {
		t.Fatal("projection invalid")
	}
	if len(fields) != 12 {
		t.Fatal("public admission added credentials, private inputs or a pass marker")
	}
}
func TestAdmitCommandRefusesPathFlagsAndExtraArguments(t *testing.T) {
	for _, args := range [][]string{{"admit", "/outside"}, {"admit", "--plan", "/outside"}, {"admit", "--endpoint", "https://outside"}, {"arbitrary-command"}} {
		var out bytes.Buffer
		cmd := newScenarioCommand(bytes.NewReader(encodePureNASInput(t, pureNASInput(t))), &out)
		cmd.SetArgs(args)
		if cmd.Execute() == nil {
			t.Fatal("generic path/endpoint/command override accepted")
		}
	}
}
