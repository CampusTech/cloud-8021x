package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStageOrderingDoesNotStartSourceBeforePrimitiveAndMigration(t *testing.T) {
	for _, stage := range []string{"assemble", "start-primitive", "start-original"} {
		steps, err := stageOrder(stage)
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(steps, ",")
		if stage == "assemble" && strings.Contains(joined, "start") {
			t.Fatal("assembly starts services")
		}
		if stage == "start-original" {
			for _, pair := range [][2]string{{"verify-primitive", "stop-primitive"}, {"stop-primitive", "start-installed-api"}, {"initialize-postgres", "start-nodes"}, {"start-nodes", "migrate-blue"}, {"migrate-blue", "start-blue-services"}} {
				a, b := strings.Index(joined, pair[0]), strings.Index(joined, pair[1])
				if a < 0 || b <= a {
					t.Fatalf("unsafe order %v: %s", pair, joined)
				}
			}
			if strings.Contains(joined, "activate-green") {
				t.Fatal("platform invented activation")
			}
		}
	}
	if _, err := stageOrder("activate-green"); err == nil {
		t.Fatal("unknown stage accepted")
	}
}

func TestPrimitiveMarkerOrInstalledResultCannotStartOriginal(t *testing.T) {
	application := strings.Repeat("a", 64)
	for _, raw := range []string{`{"ready":true}`, `{"schema":1,"gate":"installed-traffic","phase":"post-activation"}`, `{"schema":1,"gate":"primitive-contract","phase":"primitive-only","application_sha256":"` + application + `"}`} {
		if validatePrimitiveResult([]byte(raw), application) == nil {
			t.Fatal("incomplete or wrong-gate result accepted")
		}
	}
	good := primitiveResult{Schema: 1, Gate: "primitive-contract", ApplicationSHA256: application, Phase: "primitive-only", SecretPublication: true, SecretPreservation: true, FleetUncertainty: true, OTLPDecoding: true, EvidenceSHA256: strings.Repeat("b", 64), Records: 1, Metrics: 1}
	raw, _ := json.Marshal(good)
	if e := validatePrimitiveResult(raw, application); e != nil {
		t.Fatal(e)
	}
}
func TestInventoryCannotSerializeReadiness(t *testing.T) {
	p := validPlan()
	raw, e := json.Marshal(makeInventory(inputs{Plan: p, Files: map[string][]byte{}}, strings.Repeat("b", 64)))
	if e != nil {
		t.Fatal(e)
	}
	for _, forbidden := range []string{`"ready"`, `"status"`, `"activated"`, `"receipt"`} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatal("inventory asserts product success")
		}
	}
	for _, required := range []string{`"plan_sha256"`, `"machine_id"`, `"config_sha256"`, `"auxiliary"`} {
		if !strings.Contains(string(raw), required) {
			t.Fatal("stable inventory wire missing")
		}
	}
}
