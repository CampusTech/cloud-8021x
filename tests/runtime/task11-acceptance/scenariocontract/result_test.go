package scenariocontract

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting"
)

func resultFor(r Request) Result {
	at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	return Result{Schema: 1, Kind: "scenario-operation", AttemptID: r.AttemptID, Sequence: r.Sequence, Action: r.Action, Pins: r.Pins, RequestSHA256: strings.Repeat("d", 64), StartedAt: at, FinishedAt: at.Add(time.Second), Retired: true}
}
func validLedger(r Request) LedgerObservation {
	key := [4]string{"10.203.11.40", "10.203.11.40", "020000000040", r.Sessions[0]}
	id := strings.Repeat("e", 64)
	at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	return LedgerObservation{Deployment: "task11-green", Database: "cloud8021x_task11_green", Epoch: at.Add(-time.Hour), ConfigSHA256: strings.Repeat("f", 64), ReadOnly: true, Isolation: "repeatable-read", Sessions: []SessionObservation{{SessionKey: accounting.SessionKey(key), State: accounting.State{Initialized: true, Upload: math.MaxUint64, Bits: 64, LastSeen: at}}}, Observations: []EventObservation{{EventID: id, IntakeID: 1, SessionKey: accounting.SessionKey(key), ReceivedAt: at, Event: accounting.Event{ID: id, Key: key, Status: "Interim-Update", Upload: math.MaxUint64, Bits: 64, Received: at}, Reason: "baseline"}}, Outbox: []WorkObservation{{ID: "accounting:" + id, Kind: "outbox", Payload: []byte(" { \"large\" : 18446744073709551615, \"escaped\" : \"a\\u0020b\" } "), CreatedAt: at, State: "succeeded", Receipt: []byte(" { \"delivered\" : true } "), Attempts: []AttemptObservation{{Generation: 1, Owner: "task11-worker", StartedAt: at, Receipt: []byte("{ \"large\": 18446744073709551615 }")}}}}}
}
func TestLedgerTransportPreservesOpaqueBytesAndUnsignedCounters(t *testing.T) {
	r := validRequest("read-accounting")
	r.Node = "green-primary"
	r.Sessions = []string{"task11-chosen"}
	v := resultFor(r)
	ledger := validLedger(r)
	v.Ledger = &ledger
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	got, e := DecodeResult(raw, r, v.RequestSHA256)
	if e != nil {
		t.Fatal(e)
	}
	if got.Ledger.Sessions[0].State.Upload != math.MaxUint64 || got.Ledger.Observations[0].Event.Upload != math.MaxUint64 {
		t.Fatal("uint64 counter lost precision")
	}
	a, b := v.Ledger.Outbox[0], got.Ledger.Outbox[0]
	if !bytes.Equal(a.Payload, b.Payload) || !bytes.Equal(a.Receipt, b.Receipt) || !bytes.Equal(a.Attempts[0].Receipt, b.Attempts[0].Receipt) {
		t.Fatal("stored payload/receipt bytes reconstructed")
	}
}
func TestResultRejectsUnretiredSubstitutedAndMismatchedBodies(t *testing.T) {
	r := validRequest("read-accounting")
	r.Node = "green-primary"
	r.Sessions = []string{"task11-chosen"}
	v := resultFor(r)
	l := validLedger(r)
	v.Ledger = &l
	for _, mutate := range []func(*Result){func(v *Result) { v.Retired = false }, func(v *Result) { v.Kind = "pass" }, func(v *Result) { v.RequestSHA256 = strings.Repeat("a", 64) }, func(v *Result) { v.PlatformSHA256 = strings.Repeat("a", 63) + "b" }, func(v *Result) { v.FinishedAt = v.StartedAt.Add(-time.Second) }, func(v *Result) { v.AttemptID = "task11-" + strings.Repeat("c", 32) }, func(v *Result) { v.Sequence++ }, func(v *Result) { v.Probe = &PairObservation{} }, func(v *Result) { v.Ledger = nil }} {
		b := v
		mutate(&b)
		raw, _ := json.Marshal(b)
		if _, e := DecodeResult(raw, r, v.RequestSHA256); e == nil {
			t.Fatal("unsafe result accepted")
		}
	}
	raw, _ := json.Marshal(v)
	for _, b := range [][]byte{append(raw, []byte(" {}")...), []byte(strings.Replace(string(raw), `"schema":1`, `"schema":1,"schema":1`, 1)), []byte(strings.Replace(string(raw), `"kind":"scenario-operation"`, `"kind":"scenario-operation","class":"secret"`, 1)), append(bytes.Repeat([]byte(" "), MaxResultBytes), raw...)} {
		if _, e := DecodeResult(b, r, v.RequestSHA256); e == nil {
			t.Fatal("unsafe result JSON accepted")
		}
	}
}
func TestLedgerBoundsAndForeignRowsRefused(t *testing.T) {
	r := validRequest("read-accounting")
	r.Node = "green-primary"
	r.Sessions = []string{"task11-chosen"}
	for name, mutate := range map[string]func(*LedgerObservation){
		"database": func(l *LedgerObservation) { l.Database = "production" }, "write": func(l *LedgerObservation) { l.ReadOnly = false }, "isolation": func(l *LedgerObservation) { l.Isolation = "read-committed" },
		"events": func(l *LedgerObservation) { l.Observations = make([]EventObservation, 129) }, "intervals": func(l *LedgerObservation) { l.Intervals = make([]IntervalObservation, 129) }, "work": func(l *LedgerObservation) { l.Outbox = make([]WorkObservation, 257) },
		"opaque-budget": func(l *LedgerObservation) { l.Outbox[0].Payload = bytes.Repeat([]byte("x"), MaxOpaqueBytes+1) }, "foreign-session": func(l *LedgerObservation) { l.Observations[0].Event.Key[3] = "task11-other" }, "event-id": func(l *LedgerObservation) { l.Observations[0].Event.ID = strings.Repeat("b", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			v := resultFor(r)
			l := validLedger(r)
			mutate(&l)
			v.Ledger = &l
			raw, _ := json.Marshal(v)
			if _, e := DecodeResult(raw, r, v.RequestSHA256); e == nil {
				t.Fatal("unsafe ledger accepted")
			}
		})
	}
}
func TestCASelectionIsBoundedCanonicalAndIndependent(t *testing.T) {
	p := strings.Repeat("a", 64)
	v := CASelection{Schema: 1, AttemptID: "task11-" + strings.Repeat("b", 32), IssuanceSequence: 1, ResultSHA256: p, Authority: "ec", Serial: "1234", LeafDERSHA256: p, OriginalRootSHA256: p, OriginalIntermediateSHA256: p}
	raw, _ := json.Marshal(v)
	if _, e := DecodeCASelection(raw); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*CASelection){func(v *CASelection) { v.Serial = "01234" }, func(v *CASelection) { v.Serial = "0" }, func(v *CASelection) { v.Serial = "-1" }, func(v *CASelection) { v.Serial = strings.Repeat("9", 65) }, func(v *CASelection) { v.Authority = "other" }, func(v *CASelection) { v.IssuanceSequence = 0 }, func(v *CASelection) { v.ResultSHA256 = "" }, func(v *CASelection) { v.AttemptID = "../other" }} {
		c := v
		mutate(&c)
		raw, _ := json.Marshal(c)
		if _, e := DecodeCASelection(raw); e == nil {
			t.Fatal("unsafe issued selection accepted")
		}
	}
}
