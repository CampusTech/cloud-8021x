package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

func TestOuterCADriverSelectsRealOriginalLeafBeforeReadOnlyDatabaseObservation(t *testing.T) {
	f := purePriorNASInput(t)
	p, e := decodeNASPlan(f.input.PlanBytes, f.input.PlanSHA256)
	if e != nil {
		t.Fatal(e)
	}
	var original sc.Result
	_ = json.Unmarshal(f.input.Prior.ResultBytes, &original)
	root, _ := filepath.EvalSymlinks(t.TempDir())
	_ = os.Chmod(root, 0700)
	s, e := openOuterStore(root, os.Getuid())
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	a := outerAttempt{Schema: 1, Case: p.Scenario.Case, AttemptID: original.AttemptID, PlanSHA256: f.input.PlanSHA256}
	actions := []string{}
	invoke := func(_ context.Context, r sc.Request) (retiredOperation, error) {
		actions = append(actions, r.Action)
		v := original
		v.Sequence = r.Sequence
		v.Action = r.Action
		requestRaw, _ := json.Marshal(r)
		v.RequestSHA256 = digestBytes(requestRaw)
		if r.Action == "read-ca-issued" {
			selectionRaw, e := s.read("ca-selections", original.AttemptID+"-1.json", 2048)
			if e != nil {
				t.Fatal(e)
			}
			selection, e := sc.DecodeCASelection(selectionRaw)
			if e != nil || r.SelectionSHA256 != digestBytes(selectionRaw) {
				t.Fatal("pre-read independent selection absent")
			}
			v.CA = nil
			v.CAIssued = &sc.CAObservation{Authority: "rsa", Database: "stepca_rsa", ReadOnly: true, Isolation: "repeatable-read", Serial: selection.Serial, SelectionSHA256: r.SelectionSHA256, IssuanceResultSHA256: selection.ResultSHA256, LeafDERSHA256: selection.LeafDERSHA256, CertificateKey: []byte(selection.Serial), CertificateDER: original.CA.Issued.LeafDER, CertificateDataPresent: true, CertificateDataKey: []byte(selection.Serial), CertificateData: []byte(`{"provisioner":{"id":"scep/wifi-scep","name":"wifi-scep","type":"SCEP"}}`)}
		}
		raw, _ := json.Marshal(v)
		return retiredOperation{request: r, result: v, raw: raw}, nil
	}
	ops, e := executeCAActions(context.Background(), s, p, a, "original", nil, invoke)
	if e != nil || len(ops) != 2 || len(actions) != 2 || actions[0] != "nas-ca-original" || actions[1] != "read-ca-issued" {
		t.Fatal("original real issuance then DB route absent", e)
	}
	if _, e = executeCAActions(context.Background(), s, p, a, "adopted", nil, invoke); e == nil {
		t.Fatal("adoption without original DB proof")
	}
	if _, e = executeCAActions(context.Background(), s, p, a, "original", ops, invoke); e == nil {
		t.Fatal("original operation automatically rerun")
	}
}
