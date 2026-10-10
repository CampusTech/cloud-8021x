package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProducerIncludesPinnedUnenrolledEAPCase(t *testing.T) {
	bundle, err := prepareNASBundle(producerFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Plans["eap-unenrolled.json"]) == 0 {
		t.Fatal("installed scenario producer has no independently pinned unenrolled EAP rejection case")
	}
}

func TestUnenrolledCaseAdmitsOnlyItsFourFixedRequestPositions(t *testing.T) {
	bundle, e := prepareNASBundle(producerFixture(t))
	if e != nil {
		t.Fatal(e)
	}
	raw := bundle.Plans["eap-unenrolled.json"]
	p, e := decodeNASPlan(raw, digestBytes(raw))
	if e != nil {
		t.Fatal(e)
	}
	requests, e := accountingRequests(p.Scenario, "task11-"+strings.Repeat("1", 32), digestBytes(raw))
	if e != nil {
		t.Fatal(e)
	}
	if len(requests) != 4 {
		t.Fatal("rejection graph changed")
	}
	for _, r := range requests {
		rq, _ := json.Marshal(r)
		input := nasPrivateInput{Schema: 1, RequestBytes: rq, RequestSHA256: digestBytes(rq), PlanBytes: raw, PlanSHA256: digestBytes(raw)}
		if _, e := admitNASInput(encodePureNASInput(t, input)); e != nil {
			t.Fatal("valid fixed rejection action refused", e)
		}
		wrong := r
		wrong.Sequence = 5
		if wrong.Validate() != nil {
			t.Fatal("test wrong-sequence request not otherwise valid")
		}
		if validateCaseRequest(p.Scenario, wrong) == nil {
			t.Fatal("negative action accepted outside exact graph position")
		}
	}
	r := requests[2]
	r.Action = "nas-duplicates"
	if r.Validate() != nil {
		t.Fatal("closed alternate request invalid")
	}
	if validateCaseRequest(p.Scenario, r) == nil {
		t.Fatal("negative case admits accounting duplicate traffic")
	}
}
