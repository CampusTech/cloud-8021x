package main

import (
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

func TestDriverRequestsKeepControllerPinsAndBoundedActions(t *testing.T) {
	attempt := "task11-" + strings.Repeat("1", 32)
	planPin := strings.Repeat("9", 64)
	cases := map[string][]string{
		"native-accounting": {"probe-active-pair", "read-accounting", "nas-native", "read-accounting"},
		"ongoing-baseline":  {"probe-active-pair", "read-accounting", "nas-ongoing", "read-accounting"},
		"duplicate-pair":    {"probe-active-pair", "read-accounting", "nas-duplicates", "read-accounting"},
		"ha-primary":        {"probe-active-pair", "read-accounting", "stop-green-primary", "nas-native", "start-green-primary", "probe-active-pair", "read-accounting", "reboot-green-primary", "probe-active-pair"},
		"postgres-outage":   {"probe-active-pair", "read-accounting", "stop-postgres", "nas-outage", "start-postgres", "read-accounting", "probe-active-pair"},
		"business-outage":   {"probe-active-pair", "read-accounting", "intake-unavailable", "nas-native", "read-accounting", "reboot-green-primary", "probe-active-pair", "read-accounting", "intake-ready", "read-accounting"},
	}
	for kind, wanted := range cases {
		t.Run(kind, func(t *testing.T) {
			p := fixturePlan()
			p.Scenario = kind
			p.Case = kind
			switch kind {
			case "ongoing-baseline":
				p.Case = "ongoing-interim"
				p.Events = p.Events[1:]
			case "postgres-outage", "business-outage":
				p.OutageSeconds = 20
			case "ha-primary":
				p.Node = "green-secondary"
				p.Target = "10.203.11.22"
				p.Namespace = "c11-gs"
				p.Machine = "task11-green-secondary"
			}
			requests, e := accountingRequests(p, attempt, planPin)
			if e != nil {
				t.Fatal(e)
			}
			if len(requests) != len(wanted) || len(requests) > scenariocontract.MaxSequence {
				t.Fatal("missing/unbounded genuine actions")
			}
			for i, r := range requests {
				if e := r.Validate(); e != nil {
					t.Fatal(e)
				}
				if r.Action != wanted[i] || r.Sequence != i+1 || r.AttemptID != attempt || r.PlanSHA256 != planPin || r.PlatformSHA256 != p.PlatformSHA256 || r.EnrollmentSHA256 != p.EnrollmentSHA256 || r.ApplicationSHA256 != p.ApplicationSHA256 || r.ScenarioSHA256 != p.SelfSHA256 {
					t.Fatal("stale/foreign controller pin or action")
				}
				if r.Action == "read-accounting" && (r.Node != p.Node || len(r.Sessions) != 1 || r.Sessions[0] != p.Session) {
					t.Fatal("unselected SQL projection")
				}
				if strings.HasPrefix(r.Action, "nas-") && (r.Node != "" || len(r.Sessions) != 0) {
					t.Fatal("NAS request overrides fixed private plan")
				}
			}
		})
	}
}
func TestDriverRefusesWrongHATargetAndUnboundPlan(t *testing.T) {
	p := fixturePlan()
	p.Scenario = "ha-primary"
	p.Case = "ha-primary"
	attempt := "task11-" + strings.Repeat("1", 32)
	if _, e := accountingRequests(p, attempt, strings.Repeat("9", 64)); e == nil {
		t.Fatal("HA traffic targeted the stopped primary")
	}
	p = fixturePlan()
	for _, bad := range [][2]string{{"arbitrary", strings.Repeat("9", 64)}, {attempt, ""}} {
		if _, e := accountingRequests(p, bad[0], bad[1]); e == nil {
			t.Fatal("unpinned/unknown irreversible attempt planned")
		}
	}
	p.Scenario = "ca-continuity"
	p.Case = "ca-rsa-continuity"
	if _, e := accountingRequests(p, attempt, strings.Repeat("9", 64)); e == nil {
		t.Fatal("CA route silently substituted accounting/FSM")
	}
}
