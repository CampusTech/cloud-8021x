package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting"
	"github.com/CampusTech/cloud-8021x/internal/adoption"
	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

func recordFixture(t *testing.T) string {
	t.Helper()
	owned, err := os.MkdirTemp(".", ".task11-records-")
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(owned)
	if err != nil {
		t.Fatal(err)
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(abs); err != nil {
			t.Error(err)
		}
	})
	root := filepath.Join(abs, "scenarios")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"requests", "results", "failures", "claims", "ca-selections"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
func recordRequest(sequence int, action string) sc.Request {
	pin := strings.Repeat("a", 64)
	r := sc.Request{Schema: 1, AttemptID: "task11-" + strings.Repeat("b", 32), Sequence: sequence, Action: action, Pins: sc.Pins{PlanSHA256: pin, PlatformSHA256: pin, EnrollmentSHA256: pin, ApplicationSHA256: pin, ScenarioSHA256: pin}}
	if action == "read-accounting" {
		r.Node = "green-primary"
		r.Sessions = []string{"task11-one"}
	}
	return r
}
func recordJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func recordPath(t *testing.T, root, dir string, r sc.Request) string {
	t.Helper()
	name, err := r.RecordName()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, dir, name)
}
func recordWrite(t *testing.T, root, dir string, r sc.Request, raw []byte) {
	t.Helper()
	if err := os.WriteFile(recordPath(t, root, dir, r), raw, 0600); err != nil {
		t.Fatal(err)
	}
}
func recordStage(r sc.Request, raw []byte) sc.Stage {
	return sc.Stage{Stage: "scenario-operation", AttemptID: r.AttemptID, Sequence: r.Sequence, RequestSHA256: adoption.Digest(raw)}
}
func recordResult(t *testing.T, r sc.Request, rawRequest []byte, at time.Time) []byte {
	t.Helper()
	v := sc.Result{Schema: 1, Kind: "scenario-operation", AttemptID: r.AttemptID, Sequence: r.Sequence, Action: r.Action, Pins: r.Pins, RequestSHA256: adoption.Digest(rawRequest), StartedAt: at, FinishedAt: at.Add(time.Second), Retired: true}
	if r.Action == "read-accounting" {
		key := [4]string{"10.203.11.40", "10.203.11.40", "020000000040", r.Sessions[0]}
		id := strings.Repeat("e", 64)
		v.Ledger = &sc.LedgerObservation{Deployment: "task11-green", Database: "cloud8021x_task11_green", Epoch: at, ConfigSHA256: strings.Repeat("f", 64), ReadOnly: true, Isolation: "repeatable-read", Sessions: []sc.SessionObservation{{SessionKey: accounting.SessionKey(key), State: accounting.State{Bits: 64, Upload: ^uint64(0)}}}, Observations: []sc.EventObservation{{EventID: id, IntakeID: 1, SessionKey: accounting.SessionKey(key), ReceivedAt: at, Event: accounting.Event{ID: id, Key: key, Received: at}}}, Outbox: []sc.WorkObservation{{ID: "accounting:" + id, Kind: "outbox", State: "succeeded", CreatedAt: at, Payload: []byte(` { "large" : 18446744073709551615, "escaped" : "a\u0020b" } `)}}}
	} else {
		v.Gate = &sc.GateObservation{State: "intake-ready", ObservedAt: at}
	}
	raw := recordJSON(t, v)
	if _, err := sc.DecodeResult(raw, r, v.RequestSHA256); err != nil {
		t.Fatal("unit result fixture invalid", err)
	}
	return raw
}
func recordOpen(t *testing.T, root string) *scenarioRecords {
	t.Helper()
	store, err := openScenarioRecordsAt(root, os.Getuid())
	if err != nil {
		t.Fatal("protected record fixture refused", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return store
}

func TestScenarioRecordAdmissionAndExclusiveCompletion(t *testing.T) {
	root := recordFixture(t)
	store := recordOpen(t, root)
	r := recordRequest(1, "intake-ready")
	raw := append([]byte(" "), recordJSON(t, r)...)
	recordWrite(t, root, "requests", r, raw)
	claim, err := store.Admit(recordStage(r, raw), r.Pins)
	if err != nil {
		t.Fatal("fresh pinned request refused", err)
	}
	if !reflect.DeepEqual(claim.Request, r) || claim.RequestSHA256 != adoption.Digest(raw) || !bytes.Equal(claim.RequestRaw, raw) || len(claim.History) != 0 {
		t.Fatal("current request bytes/pins changed")
	}
	claimed, err := os.ReadFile(recordPath(t, root, "claims", r))
	if err != nil || !bytes.Equal(claimed, raw) {
		t.Fatal("claim was not durably visible before effects", err)
	}
	info, err := os.Stat(recordPath(t, root, "claims", r))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("exclusive claim mode differs", err)
	}
	if _, err := store.Admit(recordStage(r, raw), r.Pins); err == nil {
		t.Fatal("claimed uncertain request replayed")
	}
	result := recordResult(t, r, raw, time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC))
	if err := claim.PublishResult(result); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(recordPath(t, root, "results", r))
	if err != nil || !bytes.Equal(got, result) {
		t.Fatal("result raw bytes reconstructed", err)
	}
	if err := claim.PublishResult(result); err == nil {
		t.Fatal("result overwritten")
	}
	if err := claim.Fail("operation-failed", true); err == nil {
		t.Fatal("completed result replaced with failure")
	}
}

func TestScenarioRecordSuccessfulNextSequenceAndOpaqueResult(t *testing.T) {
	root := recordFixture(t)
	store := recordOpen(t, root)
	at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	first := recordRequest(1, "read-accounting")
	raw := recordJSON(t, first)
	recordWrite(t, root, "requests", first, raw)
	claim, err := store.Admit(recordStage(first, raw), first.Pins)
	if err != nil {
		t.Fatal(err)
	}
	result := recordResult(t, first, raw, at)
	if err := claim.PublishResult(result); err != nil {
		t.Fatal(err)
	}
	second := recordRequest(2, "intake-ready")
	secondRaw := recordJSON(t, second)
	recordWrite(t, root, "requests", second, secondRaw)
	next, err := store.Admit(recordStage(second, secondRaw), second.Pins)
	if err != nil {
		t.Fatal("retired exact predecessor refused", err)
	}
	if len(next.History) != 1 || !bytes.Equal(next.History[0].Result.Ledger.Outbox[0].Payload, []byte(` { "large" : 18446744073709551615, "escaped" : "a\u0020b" } `)) || next.History[0].Result.Ledger.Sessions[0].State.Upload != ^uint64(0) {
		t.Fatal("opaque predecessor bytes/counters changed")
	}
	if err := next.PublishResult(recordResult(t, second, secondRaw, at)); err == nil {
		t.Fatal("current result overlaps prior completion")
	}
	if err := next.PublishResult(recordResult(t, second, secondRaw, at.Add(time.Second))); err != nil {
		t.Fatal("valid next completion refused", err)
	}
}

func TestScenarioRecordRejectsCurrentAndFutureUncertainty(t *testing.T) {
	for _, dir := range []string{"claims", "results", "failures"} {
		for _, sequence := range []int{1, 2, sc.MaxSequence} {
			t.Run(dir+"-"+string(rune('a'+sequence)), func(t *testing.T) {
				root := recordFixture(t)
				store := recordOpen(t, root)
				r := recordRequest(1, "intake-ready")
				raw := recordJSON(t, r)
				recordWrite(t, root, "requests", r, raw)
				future := r
				future.Sequence = sequence
				recordWrite(t, root, dir, future, []byte(`{}`))
				if _, err := store.Admit(recordStage(r, raw), r.Pins); err == nil {
					t.Fatal("retained current/future uncertainty admitted")
				}
				if _, err := os.Stat(recordPath(t, root, "claims", r)); dir != "claims" || sequence != 1 {
					if err == nil {
						t.Fatal("refusal created claim")
					}
				}
			})
		}
	}
}

func TestScenarioRecordRejectsBrokenPriorHistory(t *testing.T) {
	for _, change := range []string{"missing-claim", "missing-result", "failure", "changed-claim", "unretired-result", "substituted-result", "changed-request-pin"} {
		t.Run(change, func(t *testing.T) {
			root := recordFixture(t)
			store := recordOpen(t, root)
			at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
			first := recordRequest(1, "intake-ready")
			raw := recordJSON(t, first)
			recordWrite(t, root, "requests", first, raw)
			recordWrite(t, root, "claims", first, raw)
			result := recordResult(t, first, raw, at)
			recordWrite(t, root, "results", first, result)
			switch change {
			case "missing-claim":
				if err := os.Remove(recordPath(t, root, "claims", first)); err != nil {
					t.Fatal(err)
				}
			case "missing-result":
				if err := os.Remove(recordPath(t, root, "results", first)); err != nil {
					t.Fatal(err)
				}
			case "failure":
				recordWrite(t, root, "failures", first, []byte(`{}`))
			case "changed-claim":
				recordWrite(t, root, "claims", first, append([]byte(" "), raw...))
			case "unretired-result":
				recordWrite(t, root, "results", first, []byte(strings.Replace(string(result), `"retired":true`, `"retired":false`, 1)))
			case "substituted-result":
				recordWrite(t, root, "results", first, []byte(strings.Replace(string(result), adoption.Digest(raw), strings.Repeat("c", 64), 1)))
			case "changed-request-pin":
				first.PlanSHA256 = strings.Repeat("c", 64)
				recordWrite(t, root, "requests", first, recordJSON(t, first))
			}
			second := recordRequest(2, "intake-ready")
			nextRaw := recordJSON(t, second)
			recordWrite(t, root, "requests", second, nextRaw)
			if _, err := store.Admit(recordStage(second, nextRaw), second.Pins); err == nil {
				t.Fatal("missing/failed/unretired/substituted prior state admitted")
			}
		})
	}
}

func TestScenarioRecordRejectsPinsAliasesAndUnsafeFiles(t *testing.T) {
	for _, change := range []string{"stage-pin", "independent-pins", "alias", "request-symlink", "request-hardlink", "request-mode", "request-bound", "root-mode", "subdir-mode", "subdir-symlink", "swapped-root", "swapped-subdir"} {
		t.Run(change, func(t *testing.T) {
			root := recordFixture(t)
			store := recordOpen(t, root)
			r := recordRequest(1, "intake-ready")
			raw := recordJSON(t, r)
			recordWrite(t, root, "requests", r, raw)
			stage := recordStage(r, raw)
			pins := r.Pins
			switch change {
			case "stage-pin":
				stage.RequestSHA256 = strings.Repeat("c", 64)
			case "independent-pins":
				pins.PlatformSHA256 = strings.Repeat("c", 64)
			case "alias":
				raw = []byte(strings.Replace(string(raw), `"action"`, `"Action"`, 1))
				recordWrite(t, root, "requests", r, raw)
				stage = recordStage(r, raw)
			case "request-symlink":
				path := recordPath(t, root, "requests", r)
				if err := os.Rename(path, path+".actual"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".actual", path); err != nil {
					t.Fatal(err)
				}
			case "request-hardlink":
				if err := os.Link(recordPath(t, root, "requests", r), filepath.Join(root, "linked")); err != nil {
					t.Fatal(err)
				}
			case "request-mode":
				if err := os.Chmod(recordPath(t, root, "requests", r), 0644); err != nil {
					t.Fatal(err)
				}
			case "request-bound":
				raw = bytes.Repeat([]byte(" "), sc.MaxRequestBytes+1)
				recordWrite(t, root, "requests", r, raw)
				stage = recordStage(r, raw)
			case "root-mode":
				if err := os.Chmod(root, 0750); err != nil {
					t.Fatal(err)
				}
			case "subdir-mode":
				if err := os.Chmod(filepath.Join(root, "claims"), 0750); err != nil {
					t.Fatal(err)
				}
			case "subdir-symlink":
				old := filepath.Join(root, "claims")
				if err := os.Rename(old, old+".actual"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(old+".actual", old); err != nil {
					t.Fatal(err)
				}
			case "swapped-root":
				if err := os.Rename(root, root+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
			case "swapped-subdir":
				old := filepath.Join(root, "claims")
				if err := os.Rename(old, old+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(old, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.Admit(stage, pins); err == nil {
				t.Fatal("substituted pins/alias/unsafe inode admitted")
			}
		})
	}
}

func TestScenarioRecordFailureRetainsClaimAndPublicCode(t *testing.T) {
	root := recordFixture(t)
	store := recordOpen(t, root)
	r := recordRequest(1, "intake-ready")
	raw := recordJSON(t, r)
	recordWrite(t, root, "requests", r, raw)
	claim, err := store.Admit(recordStage(r, raw), r.Pins)
	if err != nil {
		t.Fatal(err)
	}
	if err := claim.Fail("postgresql://synthetic-secret", true); err == nil {
		t.Fatal("raw error/credential accepted as code")
	}
	if err := claim.Fail("operation-uncertain", true); err != nil {
		t.Fatal(err)
	}
	failure, err := os.ReadFile(recordPath(t, root, "failures", r))
	if err != nil || !bytes.Contains(failure, []byte(`"uncertain":true`)) || bytes.Contains(failure, []byte("synthetic-secret")) {
		t.Fatal("bounded public failure missing or exposed error", err)
	}
	claimed, err := os.ReadFile(recordPath(t, root, "claims", r))
	if err != nil || !bytes.Equal(claimed, raw) {
		t.Fatal("failure removed/rewrote durable claim", err)
	}
	if err := claim.Fail("operation-uncertain", true); err == nil {
		t.Fatal("failure overwritten")
	}
	if err := claim.PublishResult(recordResult(t, r, raw, time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC))); err == nil {
		t.Fatal("failed operation published success")
	}
	if _, err := store.Admit(recordStage(r, raw), r.Pins); err == nil {
		t.Fatal("failed uncertain operation replayed")
	}
}

func TestScenarioRecordOpenRejectsUnsafeRootAndDirs(t *testing.T) {
	for _, change := range []string{"root-mode", "dir-mode", "dir-symlink", "wrong-owner"} {
		t.Run(change, func(t *testing.T) {
			root := recordFixture(t)
			uid := os.Getuid()
			switch change {
			case "root-mode":
				if err := os.Chmod(root, 0750); err != nil {
					t.Fatal(err)
				}
			case "dir-mode":
				if err := os.Chmod(filepath.Join(root, "claims"), 0750); err != nil {
					t.Fatal(err)
				}
			case "dir-symlink":
				old := filepath.Join(root, "claims")
				if err := os.Rename(old, old+".actual"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(old+".actual", old); err != nil {
					t.Fatal(err)
				}
			case "wrong-owner":
				uid++
			}
			if store, err := openScenarioRecordsAt(root, uid); err == nil {
				_ = store.Close()
				t.Fatal("unsafe store admitted")
			}
		})
	}
	if os.Geteuid() != 0 {
		if store, err := openScenarioRecords(); err == nil {
			_ = store.Close()
			t.Fatal("nonroot production store admitted")
		}
	}
}

func TestScenarioRecordRechecksAfterClaimWithoutOverwrite(t *testing.T) {
	for _, change := range []string{"changed-request", "changed-claim", "root-swap", "result-dir-swap", "result-symlink", "future-claim", "unretired-result", "wrong-result-hash"} {
		t.Run(change, func(t *testing.T) {
			root := recordFixture(t)
			store := recordOpen(t, root)
			r := recordRequest(1, "intake-ready")
			raw := recordJSON(t, r)
			recordWrite(t, root, "requests", r, raw)
			claim, err := store.Admit(recordStage(r, raw), r.Pins)
			if err != nil {
				t.Fatal(err)
			}
			result := recordResult(t, r, raw, time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC))
			switch change {
			case "changed-request":
				recordWrite(t, root, "requests", r, append([]byte(" "), raw...))
			case "changed-claim":
				recordWrite(t, root, "claims", r, append([]byte(" "), raw...))
			case "root-swap":
				if err := os.Rename(root, root+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
			case "result-dir-swap":
				dir := filepath.Join(root, "results")
				if err := os.Rename(dir, dir+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
			case "result-symlink":
				if err := os.Symlink(recordPath(t, root, "requests", r), recordPath(t, root, "results", r)); err != nil {
					t.Fatal(err)
				}
			case "future-claim":
				future := r
				future.Sequence = 2
				recordWrite(t, root, "claims", future, raw)
			case "unretired-result":
				result = []byte(strings.Replace(string(result), `"retired":true`, `"retired":false`, 1))
			case "wrong-result-hash":
				result = []byte(strings.Replace(string(result), adoption.Digest(raw), strings.Repeat("c", 64), 1))
			}
			if err := claim.PublishResult(result); err == nil {
				t.Fatal("changed/uncertain state completed")
			}
		})
	}
}

// This public certificate is synthetic wire data, not a product-issued or signed
// installed receipt. The test exercises exact stored Result/selection binding.
func recordIssuedFixture(t *testing.T, r sc.Request, requestRaw []byte, at time.Time) (sc.Result, sc.CASelection) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spec := &x509.Certificate{SerialNumber: big.NewInt(1234), Subject: pkix.Name{CommonName: "synthetic-record-client"}, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, spec, spec, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pin := strings.Repeat("f", 64)
	v := sc.Result{Schema: 1, Kind: "scenario-operation", AttemptID: r.AttemptID, Sequence: r.Sequence, Action: r.Action, Pins: r.Pins, RequestSHA256: adoption.Digest(requestRaw), StartedAt: at, FinishedAt: at.Add(time.Second), Retired: true, CA: &sc.CAResult{Authority: "rsa", Route: "rsa-scep", Phase: "original", Peer: "10.203.11.31", RequestSHA256: pin, SignerPublicSHA256: pin, OriginalRootSHA256: pin, OriginalIntermediateSHA256: pin, OriginalDecrypterSHA256: pin, Issued: &sc.IssuedCertificate{Serial: "1234", LeafDER: der, LeafDERSHA256: adoption.Digest(der), PublicKeySHA256: adoption.Digest(public), NotBefore: spec.NotBefore, NotAfter: spec.NotAfter, Subject: spec.Subject.String(), ClientAuthOnly: true}, Response: sc.CAResponse{HTTPStatus: 200, SignatureVerified: true, TransactionBound: true, ChainVerified: true}}}
	selection := sc.CASelection{Schema: 1, AttemptID: r.AttemptID, IssuanceSequence: 1, ResultSHA256: adoption.Digest(recordJSON(t, v)), Authority: "rsa", Serial: "1234", LeafDERSHA256: adoption.Digest(der), OriginalRootSHA256: pin, OriginalIntermediateSHA256: pin}
	return v, selection
}
func TestScenarioRecordCASelectionBindsExactPriorResult(t *testing.T) {
	for _, change := range []string{"valid", "valid-read", "raw-pin", "result-pin", "authority", "serial", "leaf-pin", "root-pin", "intermediate-pin", "issuance-coordinate", "attempt", "selection-hardlink", "selection-symlink", "selected-result-changed"} {
		t.Run(change, func(t *testing.T) {
			root := recordFixture(t)
			store := recordOpen(t, root)
			first := recordRequest(1, "nas-ca-original")
			first.Authority = "rsa"
			raw := recordJSON(t, first)
			recordWrite(t, root, "requests", first, raw)
			claim, err := store.Admit(recordStage(first, raw), first.Pins)
			if err != nil {
				t.Fatal(err)
			}
			at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
			result, selection := recordIssuedFixture(t, first, raw, at)
			resultRaw := recordJSON(t, result)
			if err := claim.PublishResult(resultRaw); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "result-pin":
				selection.ResultSHA256 = strings.Repeat("c", 64)
			case "authority":
				selection.Authority = "ec"
			case "serial":
				selection.Serial = "1235"
			case "leaf-pin":
				selection.LeafDERSHA256 = strings.Repeat("c", 64)
			case "root-pin":
				selection.OriginalRootSHA256 = strings.Repeat("c", 64)
			case "intermediate-pin":
				selection.OriginalIntermediateSHA256 = strings.Repeat("c", 64)
			case "issuance-coordinate":
				selection.IssuanceSequence = 2
			case "attempt":
				selection.AttemptID = "task11-" + strings.Repeat("c", 32)
			}
			selectedRaw := recordJSON(t, selection)
			recordWrite(t, root, "ca-selections", first, selectedRaw)
			second := recordRequest(2, "nas-ca-adopted")
			second.Authority = "rsa"
			if change == "valid-read" {
				second.Action = "read-ca-issued"
				second.Authority = ""
			}
			second.IssuanceSequence = 1
			second.SelectionSHA256 = adoption.Digest(selectedRaw)
			currentRaw := recordJSON(t, second)
			recordWrite(t, root, "requests", second, currentRaw)
			next, err := store.Admit(recordStage(second, currentRaw), second.Pins)
			if err != nil {
				t.Fatal(err)
			}
			path := recordPath(t, root, "ca-selections", first)
			switch change {
			case "raw-pin":
				recordWrite(t, root, "ca-selections", first, append([]byte(" "), selectedRaw...))
			case "selection-hardlink":
				if err := os.Link(path, filepath.Join(root, "linked-selection")); err != nil {
					t.Fatal(err)
				}
			case "selection-symlink":
				if err := os.Rename(path, path+".actual"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".actual", path); err != nil {
					t.Fatal(err)
				}
			case "selected-result-changed":
				recordWrite(t, root, "results", first, append([]byte(" "), resultRaw...))
			}
			gotRaw, got, err := next.ReadCASelection()
			if change == "valid" || change == "valid-read" {
				if err != nil || !bytes.Equal(gotRaw, selectedRaw) || got != selection {
					t.Fatal("exact genuine-result selection refused/reconstructed", err)
				}
			} else if err == nil {
				t.Fatal("substituted selection or prior result admitted")
			}
		})
	}
}

func TestScenarioRecordRefusesNoncanonicalRetainedClaimAlias(t *testing.T) {
	root := recordFixture(t)
	store := recordOpen(t, root)
	r := recordRequest(1, "intake-ready")
	raw := recordJSON(t, r)
	recordWrite(t, root, "requests", r, raw)
	claim, err := store.Admit(recordStage(r, raw), r.Pins)
	if err != nil {
		t.Fatal(err)
	}
	_ = claim
	if err := os.Rename(recordPath(t, root, "claims", r), filepath.Join(root, "claims", r.AttemptID+"-01.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Admit(recordStage(r, raw), r.Pins); err == nil {
		t.Fatal("aliased retained claim permitted replay")
	}
}

func TestScenarioRecordConcurrentIndependentAdmissionsClaimOnce(t *testing.T) {
	root := recordFixture(t)
	r := recordRequest(1, "intake-ready")
	raw := recordJSON(t, r)
	recordWrite(t, root, "requests", r, raw)
	var stores []*scenarioRecords
	for range 8 {
		stores = append(stores, recordOpen(t, root))
	}
	start := make(chan struct{})
	outcomes := make(chan error, len(stores))
	var workers sync.WaitGroup
	for _, store := range stores {
		workers.Add(1)
		go func(s *scenarioRecords) {
			defer workers.Done()
			<-start
			_, err := s.Admit(recordStage(r, raw), r.Pins)
			outcomes <- err
		}(store)
	}
	close(start)
	workers.Wait()
	close(outcomes)
	accepted := 0
	for err := range outcomes {
		if err == nil {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("independent duplicate controllers admitted %d operations", accepted)
	}
	claimed, err := os.ReadFile(recordPath(t, root, "claims", r))
	if err != nil || !bytes.Equal(claimed, raw) {
		t.Fatal("concurrent exclusive claim differs", err)
	}
}
