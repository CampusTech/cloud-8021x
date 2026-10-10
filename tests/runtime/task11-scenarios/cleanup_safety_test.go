package main

import (
	"encoding/json"
	"strings"
	"testing"

	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

func TestOwnedCleanupRefusesOtherEightImmutableCases(t *testing.T) {
	bundle, e := prepareNASBundle(producerFixture(t))
	if e != nil {
		t.Fatal(e)
	}
	for name, raw := range bundle.Plans {
		if name == "native-accounting.json" {
			continue
		}
		p, e := decodeNASPlan(raw, digestBytes(raw))
		if e != nil {
			t.Fatal(e)
		}
		r := sc.Request{Schema: 1, AttemptID: "task11-" + strings.Repeat("1", 32), Sequence: 2, Action: "probe-owned-cleanup", Pins: planPins(p, digestBytes(raw))}
		rb, _ := json.Marshal(r)
		in := nasPrivateInput{Schema: 1, RequestBytes: rb, RequestSHA256: digestBytes(rb), PlanBytes: raw, PlanSHA256: digestBytes(raw)}
		if _, e = admitNASInput(encodePureNASInput(t, in)); e == nil {
			t.Fatal("cleanup escaped native accounting case", name)
		}
	}
}

func TestOwnedCleanupRefusesForeignPinsSelectorsAndSequence(t *testing.T) {
	for _, fault := range []string{"plan", "platform", "enrollment", "app", "helper", "node", "sessions", "authority", "selection", "issuance", "sequence", "prior"} {
		t.Run(fault, func(t *testing.T) {
			in := pureNASInput(t)
			r, e := sc.DecodeRequest(in.RequestBytes)
			if e != nil {
				t.Fatal(e)
			}
			r.Action = "probe-owned-cleanup"
			r.Sequence = 2
			switch fault {
			case "plan":
				r.PlanSHA256 = strings.Repeat("0", 64)
			case "platform":
				r.PlatformSHA256 = strings.Repeat("0", 64)
			case "enrollment":
				r.EnrollmentSHA256 = strings.Repeat("0", 64)
			case "app":
				r.ApplicationSHA256 = strings.Repeat("0", 64)
			case "helper":
				r.ScenarioSHA256 = strings.Repeat("0", 64)
			case "node":
				r.Node = "green-primary"
			case "sessions":
				r.Sessions = []string{"task11-foreign"}
			case "authority":
				r.Authority = "rsa"
			case "selection":
				r.SelectionSHA256 = strings.Repeat("0", 64)
			case "issuance":
				r.IssuanceSequence = 1
			case "sequence":
				r.Sequence = 3
			case "prior":
				in.Prior = &nasPriorInput{}
			}
			in.RequestBytes, _ = json.Marshal(r)
			in.RequestSHA256 = digestBytes(in.RequestBytes)
			if _, e = admitNASInput(encodePureNASInput(t, in)); e == nil {
				t.Fatal("foreign cleanup context accepted", fault)
			}
		})
	}
}
