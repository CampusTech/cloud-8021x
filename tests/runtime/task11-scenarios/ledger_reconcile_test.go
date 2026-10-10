package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting"
	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

func pureMeasuredLedger(t *testing.T) (nasPrivatePlan, sc.NASResult, sc.LedgerObservation) {
	t.Helper()
	p := pureNASPlan()
	now := p.Scenario.CollectionEpoch.Add(time.Hour)
	key, class := actualClassForPureTest(t, now)
	secret := []byte("task11-private-nas-secret")
	p.Materials["class-key"] = digestBytes(key)
	p.Materials["radius-secret"] = digestBytes(secret)
	a, e := prepareNativeAccounting(p, sc.EAPResult{Accepted: true, ResponseCode: 2, ResponseAuthenticatorSHA256: strings.Repeat("e", 64), TunnelType: 13, TunnelMediumType: 6, VLAN: 120}, class, key, secret, now, bytes.NewReader([]byte{1, 2, 3}))
	if e != nil {
		t.Fatal(e)
	}
	expected, e := deriveNASExpectations(p, class, key, now, p.Scenario.CollectionEpoch)
	if e != nil {
		t.Fatal(e)
	}
	n := a.result
	l := sc.LedgerObservation{Deployment: "task11-green", Database: "cloud8021x_task11_green", Epoch: p.Scenario.CollectionEpoch, ConfigSHA256: strings.Repeat("a", 64), ReadOnly: true, Isolation: "repeatable-read"}
	state := accounting.State{}
	for i, event := range expected.Events {
		at := now.Add(time.Duration(i) * time.Second)
		event.Received = at
		next, interval, reason := accounting.ApplyEpoch(state, event, l.Epoch)
		state = next
		k := accounting.SessionKey(event.Key)
		l.Observations = append(l.Observations, sc.EventObservation{EventID: event.ID, IntakeID: int64(i + 1), SessionKey: k, ReceivedAt: at, Event: event, Reason: reason})
		body, _ := json.Marshal(event)
		l.Outbox = append(l.Outbox, sc.WorkObservation{ID: "accounting:" + event.ID, Kind: "outbox", Payload: body, CreatedAt: at, State: "pending"})
		if interval != nil {
			l.Intervals = append(l.Intervals, sc.IntervalObservation{UsageID: interval.ID, EventID: event.ID, SessionKey: k, Interval: *interval})
			body, _ = json.Marshal(interval)
			l.Outbox = append(l.Outbox, sc.WorkObservation{ID: "usage:" + interval.ID, Kind: "outbox", Payload: body, CreatedAt: at, State: "pending"})
		}
		planned := p.Scenario.Events[i]
		n.Packets = append(n.Packets, sc.AccountingPacketResult{Peer: p.Scenario.Target, PacketID: uint8(i + 1), Status: planned.Status, Duration: planned.Duration, UploadBytes: planned.Upload, DownloadBytes: planned.Download, RequestAuthenticator: strings.Repeat("a", 32), ACK: true, ResponseCode: 5, ResponseAuthenticatorSHA256: strings.Repeat("f", 64), SentAt: at, CompletedAt: at.Add(time.Second)})
	}
	l.Sessions = []sc.SessionObservation{{SessionKey: accounting.SessionKey(expected.Events[0].Key), State: state}}
	return p, n, l
}
func TestLedgerReconciliationUsesIndependentIDsCountersAttributionAndPacketWindow(t *testing.T) {
	p, n, l := pureMeasuredLedger(t)
	if e := reconcileNativeLedger(p, n, l); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"extra-credit", "event-counter", "foreign-identity", "missing-work", "epoch", "packet-window", "reason", "session", "expected-id", "packet-counter"} {
		t.Run(name, func(t *testing.T) {
			p, n, l := pureMeasuredLedger(t)
			switch name {
			case "extra-credit":
				l.Intervals[0].Interval.Upload++
			case "event-counter":
				l.Observations[1].Event.Upload++
			case "foreign-identity":
				l.Observations[0].Event.Identity.Fingerprint = strings.Repeat("9", 64)
			case "missing-work":
				l.Outbox = l.Outbox[1:]
			case "epoch":
				l.Epoch = l.Epoch.Add(time.Second)
			case "packet-window":
				l.Observations[0].ReceivedAt = l.Observations[0].ReceivedAt.Add(-time.Hour)
			case "reason":
				l.Observations[0].Reason = "interval"
			case "session":
				l.Sessions[0].State.Upload++
			case "expected-id":
				n.Expected.EventIDs[0] = strings.Repeat("9", 64)
			case "packet-counter":
				n.Packets[1].UploadBytes++
			}
			if reconcileNativeLedger(p, n, l) == nil {
				t.Fatal("accepted mismatched evidence", name)
			}
		})
	}
}
func TestLedgerPersistenceKeepsExactStoredBytesAndOriginalTimestamps(t *testing.T) {
	_, _, a := pureMeasuredLedger(t)
	raw, _ := json.Marshal(a)
	var b sc.LedgerObservation
	if e := json.Unmarshal(raw, &b); e != nil {
		t.Fatal(e)
	}
	for i := range b.Outbox {
		b.Outbox[i].State = "succeeded"
		b.Outbox[i].Receipt = []byte(" { \"delivered\": true } ")
	}
	if e := preserveLedgerWork(a, b); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"bytes", "created", "missing", "extra"} {
		var after sc.LedgerObservation
		_ = json.Unmarshal(raw, &after)
		switch kind {
		case "bytes":
			after.Outbox[0].Payload = append([]byte(" "), after.Outbox[0].Payload...)
		case "created":
			after.Outbox[0].CreatedAt = after.Outbox[0].CreatedAt.Add(time.Second)
		case "missing":
			after.Outbox = after.Outbox[1:]
		case "extra":
			after.Outbox = append(after.Outbox, after.Outbox[0])
		}
		if preserveLedgerWork(a, after) == nil {
			t.Fatal("rewritten stored evidence", kind)
		}
	}
}

func TestLedgerPersistenceAllowsActualPendingAttemptToFinishWithoutRewritingItsIdentity(t *testing.T) {
	_, _, before := pureMeasuredLedger(t)
	at := before.Outbox[0].CreatedAt
	before.Outbox[0].Attempts = []sc.AttemptObservation{{Generation: 1, Owner: "task11-worker", StartedAt: at}}
	raw, _ := json.Marshal(before)
	var after sc.LedgerObservation
	_ = json.Unmarshal(raw, &after)
	finished := at.Add(time.Second)
	outcome := "succeeded"
	after.Outbox[0].Attempts[0].FinishedAt = &finished
	after.Outbox[0].Attempts[0].Outcome = &outcome
	after.Outbox[0].Attempts[0].Receipt = []byte(`{"delivered":true}`)
	after.Outbox[0].State = "succeeded"
	if e := preserveLedgerWork(before, after); e != nil {
		t.Fatal("actual attempt completion incorrectly treated as rewritten immutable work", e)
	}
	for _, fault := range []string{"owner", "generation", "started"} {
		var changed sc.LedgerObservation
		_ = json.Unmarshal(raw, &changed)
		switch fault {
		case "owner":
			changed.Outbox[0].Attempts[0].Owner = "other"
		case "generation":
			changed.Outbox[0].Attempts[0].Generation++
		case "started":
			changed.Outbox[0].Attempts[0].StartedAt = at.Add(time.Second)
		}
		if preserveLedgerWork(before, changed) == nil {
			t.Fatal("attempt immutable identity changed", fault)
		}
	}
}
