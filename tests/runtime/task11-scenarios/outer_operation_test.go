package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

type pureControllerRoute struct {
	request sc.Request
	raw     []byte
	steps   []string
	fault   string
}

func (f *pureControllerRoute) publishRequest(r sc.Request, raw []byte) error {
	f.steps = append(f.steps, "publish")
	f.request = r
	f.raw = append([]byte(nil), raw...)
	if f.fault == "publish" {
		return errors.New("injected")
	}
	return nil
}
func (f *pureControllerRoute) dispatch(_ context.Context, s sc.Stage) error {
	f.steps = append(f.steps, "dispatch")
	if s.AttemptID != f.request.AttemptID || s.Sequence != f.request.Sequence || s.RequestSHA256 != digestBytes(f.raw) || s.Stage != "scenario-operation" {
		return errors.New("coordinates changed")
	}
	if f.fault == "dispatch" {
		return errors.New("injected")
	}
	return nil
}
func (f *pureControllerRoute) readResult(_ context.Context, r sc.Request) ([]byte, error) {
	f.steps = append(f.steps, "read")
	if f.fault == "read" {
		return nil, errors.New("injected")
	}
	now := fixturePlan().CollectionEpoch.Add(time.Hour)
	v := sc.Result{Schema: 1, Kind: "scenario-operation", AttemptID: r.AttemptID, Sequence: r.Sequence, Action: r.Action, Pins: r.Pins, RequestSHA256: digestBytes(f.raw), StartedAt: now, FinishedAt: now.Add(time.Second), Retired: true, Ledger: &sc.LedgerObservation{Deployment: "task11-green", Database: "cloud8021x_task11_green", Epoch: fixturePlan().CollectionEpoch, ConfigSHA256: strings.Repeat("a", 64), ReadOnly: true, Isolation: "repeatable-read"}}
	if f.fault == "unretired" {
		v.Retired = false
	}
	if f.fault == "hash" {
		v.RequestSHA256 = strings.Repeat("b", 64)
	}
	return json.Marshal(v)
}
func TestOuterOperationUsesExclusiveRequestStageAndSoleRetiredDecoder(t *testing.T) {
	requests, e := accountingRequests(fixturePlan(), "task11-"+strings.Repeat("1", 32), strings.Repeat("9", 64))
	if e != nil {
		t.Fatal(e)
	}
	r := requests[2]
	f := &pureControllerRoute{}
	result, raw, e := submitOperation(context.Background(), f, r)
	if e != nil {
		t.Fatal(e)
	}
	if result.Ledger == nil || len(raw) == 0 || !bytes.Equal(f.raw, mustRequestJSON(t, r)) || strings.Join(f.steps, ",") != "publish,dispatch,read" {
		t.Fatal("request bytes/retirement/order lost")
	}
	for _, fault := range []string{"publish", "dispatch", "read", "unretired", "hash"} {
		f = &pureControllerRoute{fault: fault}
		if _, _, e = submitOperation(context.Background(), f, r); e == nil {
			t.Fatal("failed/uncertain operation accepted", fault)
		}
		if fault == "publish" && len(f.steps) != 1 || fault == "dispatch" && len(f.steps) != 2 {
			t.Fatal("continued after failed effect")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f = &pureControllerRoute{}
	if _, _, e = submitOperation(ctx, f, r); e == nil || len(f.steps) != 0 {
		t.Fatal("cancelled operation published")
	}
}
func mustRequestJSON(t *testing.T, r sc.Request) []byte {
	t.Helper()
	raw, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
