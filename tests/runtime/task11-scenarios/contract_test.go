package main

import (
	"strings"
	"testing"
	"time"
)

func fixturePlan() scenarioPlan {
	p := scenarioPlan{Schema: 1, Scenario: "native-accounting", Case: "native-accounting", PlatformSHA256: strings.Repeat("a", 64), EnrollmentSHA256: strings.Repeat("b", 64), ApplicationSHA256: strings.Repeat("c", 64), SelfSHA256: strings.Repeat("d", 64), OriginalSeedSHA256: strings.Repeat("e", 64), CollectionEpoch: time.Unix(1800000000, 0).UTC(), Node: "green-primary", Target: "10.203.11.21", Namespace: "c11-gp", Machine: "task11-green-primary", NAS: "10.203.11.40", NASNamespace: "c11-nas", Session: "task11-independent-new", Events: []plannedEvent{{Status: 1}, {Status: 3, Duration: 60, Upload: 1000, Download: 2000}, {Status: 2, Duration: 90, Upload: 1600, Download: 2900}}, OutageSeconds: 0}
	return p
}

func TestClosedPlanRejectsTargetsRolesAndNamespace(t *testing.T) {
	for _, mutate := range []func(*scenarioPlan){
		func(p *scenarioPlan) { p.Target = "127.0.0.1" },
		func(p *scenarioPlan) { p.Node = "blue-primary" },
		func(p *scenarioPlan) { p.Namespace = "c11-gs" },
		func(p *scenarioPlan) { p.Machine = "task11-green-secondary" },
		func(p *scenarioPlan) { p.NAS = "10.203.11.41" },
		func(p *scenarioPlan) { p.NASNamespace = "host" },
		func(p *scenarioPlan) { p.ApplicationSHA256 = "" },
		func(p *scenarioPlan) { p.Session = "../../outside" },
		func(p *scenarioPlan) { p.Schema = 2 },
		func(p *scenarioPlan) { p.Scenario = "arbitrary-command" },
		func(p *scenarioPlan) { p.Events[1].Upload = 1<<64 - 1 },
	} {
		p := fixturePlan()
		mutate(&p)
		if err := validatePlan(p); err == nil {
			t.Fatalf("unsafe plan accepted: %+v", p)
		}
	}
	if err := validatePlan(fixturePlan()); err != nil {
		t.Fatal(err)
	}
}

func TestOutageBoundAndFixedOrdering(t *testing.T) {
	p := fixturePlan()
	p.Scenario = "postgres-outage"
	p.Case = "postgres-outage"
	for _, seconds := range []int{0, -1, 61} {
		p.OutageSeconds = seconds
		if validatePlan(p) == nil {
			t.Fatalf("unbounded outage %d accepted", seconds)
		}
	}
	p.OutageSeconds = 20
	if err := validatePlan(p); err != nil {
		t.Fatal(err)
	}
	steps, err := scenarioSteps(p)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"fresh-active-pair", "freeze-independent-events", "readonly-before", "stop-owned-postgres", "traffic-native-response", "start-owned-postgres", "wait-ledger-replay", "readonly-after", "verify-accounting"}
	if strings.Join(steps, "|") != strings.Join(expected, "|") {
		t.Fatalf("wrong bounded outage order: %v", steps)
	}
}

func TestStaleAuditCannotAuthorizeOperation(t *testing.T) {
	p := fixturePlan()
	before := liveIdentity{Machine: p.Machine, Root: "/var/lib/cloud8021x-task11/roots/" + p.Machine, MachineID: strings.Repeat("1", 32), BootID: "11111111-2222-4333-8444-555555555555", Leader: 100, StartTicks: 17, ConfigSHA256: p.EnrollmentSHA256, ApplicationSHA256: p.ApplicationSHA256, Namespace: 10, ObservedSequence: 3}
	after := before
	after.ObservedSequence++
	if err := sameLiveIdentity(before, after); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*liveIdentity){func(v *liveIdentity) { v.Leader++ }, func(v *liveIdentity) { v.StartTicks++ }, func(v *liveIdentity) { v.BootID = "different" }, func(v *liveIdentity) { v.Namespace++ }, func(v *liveIdentity) { v.ConfigSHA256 = "" }, func(v *liveIdentity) { v.ObservedSequence = 2 }} {
		after = before
		after.ObservedSequence++
		mutate(&after)
		if sameLiveIdentity(before, after) == nil {
			t.Fatalf("stale or foreign actual identity accepted: %+v", after)
		}
	}
}

func TestPartialAttemptNeverAutomaticallyRetries(t *testing.T) {
	for _, status := range []string{"started", "uncertain", "completed", "unknown"} {
		if err := allowNewAttempt(&attemptRecord{Schema: 1, Scenario: "native-accounting", PlanSHA256: strings.Repeat("a", 64), Status: status}); err == nil {
			t.Fatalf("retained %s attempt automatically rerun", status)
		}
	}
	if err := allowNewAttempt(nil); err != nil {
		t.Fatal(err)
	}
}
