package main

import (
	"encoding/json"
	"testing"

	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

func TestNativeAccountingAdmitsPinnedOwnedCleanup(t *testing.T) {
	input := pureNASInput(t)
	request, err := scenariocontract.DecodeRequest(input.RequestBytes)
	if err != nil {
		t.Fatal(err)
	}
	request.Action = "probe-owned-cleanup"
	request.Sequence = 2
	if err := request.Validate(); err != nil {
		t.Fatalf("valid shared cleanup envelope: %v", err)
	}
	input.RequestBytes, err = json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	input.RequestSHA256 = digestBytes(input.RequestBytes)
	if _, err := admitNASInput(encodePureNASInput(t, input)); err != nil {
		t.Fatalf("independently pinned native cleanup is unreachable: %v", err)
	}
}

func TestNativeAccountingPlansExactlyOneOwnedCleanup(t *testing.T) {
	input := pureNASInput(t)
	request, err := scenariocontract.DecodeRequest(input.RequestBytes)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := decodeNASPlan(input.PlanBytes, input.PlanSHA256)
	if err != nil {
		t.Fatal(err)
	}
	actions, err := accountingRequests(plan.Scenario, request.AttemptID, input.PlanSHA256)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for i, action := range actions {
		if action.Action == "probe-owned-cleanup" {
			count++
			if i != 1 || actions[0].Action != "probe-active-pair" {
				t.Fatal("cleanup must follow the verified pair")
			}
		}
	}
	if count != 1 {
		t.Fatalf("actual native graph has %d cleanup requests; want exactly one", count)
	}
}
