package main

import (
	"encoding/json"
	"testing"
	"time"

	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

func TestLedgerSemanticTimesSurviveUTCRoundTrip(t *testing.T) {
	p, nas, original := pureMeasuredLedger(t)
	// A verified Class carries Unix time in Local; PostgreSQL/JSON returns UTC.
	// Both denote the same instant even when Local itself is a UTC zone.
	localUTC := time.FixedZone("synthetic-local-UTC", 0)
	nas.Attribution.IssuedAt = nas.Attribution.IssuedAt.In(localUTC)
	for i := range original.Observations {
		original.Observations[i].Event.Identity.IssuedAt = original.Observations[i].Event.Identity.IssuedAt.In(localUTC)
	}
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var restored sc.LedgerObservation
	if err = json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if err = reconcileNativeLedger(p, nas, restored); err != nil {
		t.Fatal("same timestamp instants rejected after actual JSON roundtrip", err)
	}
	if err = preserveLedgerWork(original, restored); err != nil {
		t.Fatal("same preserved row instants rejected after actual JSON roundtrip", err)
	}
	for _, fault := range []string{"issued", "received", "last-seen", "interval", "payload"} {
		t.Run(fault, func(t *testing.T) {
			var changed sc.LedgerObservation
			if err := json.Unmarshal(raw, &changed); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "issued":
				changed.Observations[0].Event.Identity.IssuedAt = changed.Observations[0].Event.Identity.IssuedAt.Add(time.Nanosecond)
			case "received":
				changed.Observations[0].ReceivedAt = changed.Observations[0].ReceivedAt.Add(time.Nanosecond)
			case "last-seen":
				changed.Sessions[0].State.LastSeen = changed.Sessions[0].State.LastSeen.Add(time.Nanosecond)
			case "interval":
				changed.Intervals[0].Interval.Received = changed.Intervals[0].Interval.Received.Add(time.Nanosecond)
			case "payload":
				changed.Outbox[0].Payload = append([]byte(" "), changed.Outbox[0].Payload...)
			}
			if preserveLedgerWork(original, changed) == nil {
				t.Fatal("changed instant or exact opaque payload accepted")
			}
		})
	}
}

func TestLedgerCompletedAttemptTimeRoundTripPreservesExactEvidence(t *testing.T) {
	_, _, before := pureMeasuredLedger(t)
	at := before.Outbox[0].CreatedAt.In(time.FixedZone("synthetic-local-UTC", 0))
	finished := at.Add(time.Second)
	outcome := "succeeded"
	before.Outbox[0].Attempts = []sc.AttemptObservation{{Generation: 1, Owner: "task11-worker", StartedAt: at, FinishedAt: &finished, Outcome: &outcome, Receipt: []byte(" { \"delivered\": true } ")}}
	raw, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	var after sc.LedgerObservation
	if err = json.Unmarshal(raw, &after); err != nil {
		t.Fatal(err)
	}
	if err = preserveLedgerWork(before, after); err != nil {
		t.Fatal("completed attempt equal instants rejected after JSON roundtrip", err)
	}
	for _, fault := range []string{"finished", "receipt", "outcome"} {
		t.Run(fault, func(t *testing.T) {
			var changed sc.LedgerObservation
			if err := json.Unmarshal(raw, &changed); err != nil {
				t.Fatal(err)
			}
			a := &changed.Outbox[0].Attempts[0]
			switch fault {
			case "finished":
				x := a.FinishedAt.Add(time.Nanosecond)
				a.FinishedAt = &x
			case "receipt":
				a.Receipt = append([]byte(" "), a.Receipt...)
			case "outcome":
				x := "failed"
				a.Outcome = &x
			}
			if preserveLedgerWork(before, changed) == nil {
				t.Fatal("completed attempt evidence changed")
			}
		})
	}
}
