package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

func TestPlanCaseIndependentlyBindsScenarioAndOngoingFirstStatus(t *testing.T) {
	p := fixturePlan()
	for _, bad := range []string{"", "../native-accounting", "native-accounting.json", "ca-rsa-continuity", "ongoing-interim"} {
		p.Case = bad
		if validatePlan(p) == nil {
			t.Fatal("unknown/mismatched immutable case accepted")
		}
	}
	p = fixturePlan()
	p.Scenario = "ongoing-baseline"
	p.Events = p.Events[1:]
	p.Case = "ongoing-interim"
	if e := validatePlan(p); e != nil {
		t.Fatal(e)
	}
	p.Case = "ongoing-stop"
	if validatePlan(p) == nil {
		t.Fatal("stop case substituted for independent interim baseline")
	}
	p.Events = p.Events[1:]
	if e := validatePlan(p); e != nil {
		t.Fatal(e)
	}
	p.Case = "ongoing-interim"
	if validatePlan(p) == nil {
		t.Fatal("interim case substituted for independent stop baseline")
	}
}
func TestPureAdmissionMatchesActualOpaquePlanAndSelectedSQLContext(t *testing.T) {
	input := pureNASInput(t)
	projection, e := admitNASInput(encodePureNASInput(t, input))
	if e != nil {
		t.Fatal(e)
	}
	p := pureNASPlan()
	if projection.Schema != 1 || projection.RequestSHA256 != input.RequestSHA256 || projection.PlanSHA256 != input.PlanSHA256 || projection.PlatformSHA256 != p.Scenario.PlatformSHA256 || projection.EnrollmentSHA256 != p.Scenario.EnrollmentSHA256 || projection.ApplicationSHA256 != p.Scenario.ApplicationSHA256 || projection.ScenarioSHA256 != p.Scenario.SelfSHA256 || projection.OriginalSeedSHA256 != p.OriginalSeedSHA256 || !projection.CollectionEpoch.Equal(p.Scenario.CollectionEpoch) || projection.Node != p.Scenario.Node || projection.Session != p.Scenario.Session || projection.Case != "native-accounting" || projection.Authority != "" {
		t.Fatal("public projection inferred/substituted immutable plan fields")
	}
	request, e := scenariocontract.DecodeRequest(input.RequestBytes)
	if e != nil {
		t.Fatal(e)
	}
	request.Action = "read-accounting"
	request.Node = p.Scenario.Node
	request.Sessions = []string{p.Scenario.Session}
	for _, kind := range []string{"valid", "foreign-node", "foreign-session", "extra-session", "irrelevant-gate"} {
		r := request
		r.Sessions = append([]string(nil), request.Sessions...)
		switch kind {
		case "foreign-node":
			r.Node = "green-secondary"
		case "foreign-session":
			r.Sessions = []string{"task11-foreign"}
		case "extra-session":
			r.Sessions = append(r.Sessions, "task11-extra")
		case "irrelevant-gate":
			r.Action = "stop-postgres"
			r.Node = ""
			r.Sessions = nil
		}
		raw, e := json.Marshal(r)
		if e != nil {
			t.Fatal(e)
		}
		v := input
		v.RequestBytes = raw
		v.RequestSHA256 = digestBytes(raw)
		_, e = admitNASInput(encodePureNASInput(t, v))
		if (e == nil) != (kind == "valid") {
			t.Fatal("admission did not independently bind selected action/Node/Sessions")
		}
	}
}
func TestCAAdmissionAuthorityDerivesOnlyFromImmutableCase(t *testing.T) {
	f := purePriorNASInput(t)
	projection, e := admitNASInput(encodePureNASInput(t, f.input))
	if e != nil {
		t.Fatal(e)
	}
	if projection.Case != "ca-rsa-continuity" || projection.Authority != "rsa" {
		t.Fatal("CA authority inferred after request instead of from immutable case")
	}
	p := pureNASPlan()
	p.Scenario.Scenario = "ca-continuity"
	p.Scenario.Case = "ca-ec-continuity"
	planBytes, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	input := pureNASInput(t)
	input.PlanBytes = planBytes
	input.PlanSHA256 = digestBytes(planBytes)
	request, e := scenariocontract.DecodeRequest(input.RequestBytes)
	if e != nil {
		t.Fatal(e)
	}
	request.Action = "nas-ca-original"
	request.Authority = "ec"
	request.PlanSHA256 = input.PlanSHA256
	for _, authority := range []string{"ec", "rsa"} {
		request.Authority = authority
		input.RequestBytes, e = json.Marshal(request)
		if e != nil {
			t.Fatal(e)
		}
		input.RequestSHA256 = digestBytes(input.RequestBytes)
		projection, e = admitNASInput(encodePureNASInput(t, input))
		if (e == nil) != (authority == "ec") {
			t.Fatal("immutable CA case was overridden")
		}
		if e == nil && projection.Authority != "ec" {
			t.Fatal("EC projection authority changed")
		}
	}
	input.RequestSHA256 = strings.Repeat("0", 64)
	if _, e := admitNASInput(encodePureNASInput(t, input)); e == nil {
		t.Fatal("unpinned admission accepted")
	}
}
