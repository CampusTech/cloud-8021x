package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/jobs"
)

func TestPostgresWorkClaims(t *testing.T) {
	admin, c := integration(t)
	s := runtimeStore(t, admin, c)
	ctx := context.Background()
	if err := s.Reserve(ctx, "command:1", "certificate", json.RawMessage(`{"device_id":"d"}`)); err != nil {
		t.Fatal(err)
	}
	a, err := s.Claim(ctx, "certificate", "worker-a", time.Second)
	if err != nil || a == nil {
		t.Fatal(a, err)
	}
	if err = s.StartAttempt(ctx, *a); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.pool.Exec(ctx, "UPDATE ledger.work SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1", a.ID); err != nil {
		t.Fatal(err)
	}
	b, err := s.Claim(ctx, "certificate", "worker-b", time.Second)
	if err != nil || b != nil {
		t.Fatal("uncertain work reclaimed", b, err)
	}
	if err = s.FinishAttempt(ctx, *a, jobs.Succeeded, json.RawMessage(`{}`)); !errors.Is(err, jobs.ErrFenced) {
		t.Fatal("stale result accepted", err)
	}
	var state, outcome string
	if err = admin.pool.QueryRow(ctx, "SELECT w.state,a.outcome FROM ledger.work w JOIN ledger.attempts a ON a.work_id=w.id WHERE w.id='command:1'").Scan(&state, &outcome); err != nil || state != "quarantine" || outcome != "uncertain" {
		t.Fatal(state, outcome, err)
	}
}

func TestPostgresLeaseGenerationsAndOutcomes(t *testing.T) {
	admin, c := integration(t)
	reset(t, admin)
	s := runtimeStore(t, admin, c)
	ctx := context.Background()
	if err := s.Reserve(ctx, "reclaim", "jobs", json.RawMessage(`{"n":1}`)); err != nil {
		t.Fatal(err)
	}
	old, err := s.Claim(ctx, "jobs", "one", time.Minute)
	if err != nil || old == nil {
		t.Fatal(err)
	}
	if _, err = admin.pool.Exec(ctx, "UPDATE ledger.work SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1", old.ID); err != nil {
		t.Fatal(err)
	}
	current, err := s.Claim(ctx, "jobs", "two", time.Minute)
	if err != nil || current == nil || current.Generation != old.Generation+1 {
		t.Fatal("unstarted reservation not reclaimed", current, err)
	}
	if err = s.StartAttempt(ctx, *old); !errors.Is(err, jobs.ErrFenced) {
		t.Fatal("old generation started", err)
	}
	if err = s.StartAttempt(ctx, *current); err != nil {
		t.Fatal(err)
	}
	if err = s.FinishAttempt(ctx, *current, jobs.Partial, json.RawMessage(`{"rejected":1}`)); err != nil {
		t.Fatal(err)
	}
	state, err := s.LookupWork(ctx, current.ID)
	if err != nil || state.State != "quarantine" || len(state.Payload) == 0 || len(state.Receipt) == 0 {
		t.Fatal("partial result not retained", state, err)
	}
	if next, err := s.Claim(ctx, "jobs", "three", time.Minute); err != nil || next != nil {
		t.Fatal("partial batch retried", next, err)
	}
	if err = s.Reserve(ctx, "reclaim", "jobs", json.RawMessage(`{"n":2}`)); !errors.Is(err, jobs.ErrConflict) {
		t.Fatal("reservation content changed", err)
	}
	if err = s.Reserve(ctx, "success", "jobs", json.RawMessage(`{"n":3}`)); err != nil {
		t.Fatal(err)
	}
	claim, err := s.Claim(ctx, "jobs", "three", time.Minute)
	if err != nil || claim == nil {
		t.Fatal(err)
	}
	if err = s.StartAttempt(ctx, *claim); err != nil {
		t.Fatal(err)
	}
	if err = s.FinishAttempt(ctx, *claim, jobs.Succeeded, json.RawMessage(`{"ack":true}`)); err != nil {
		t.Fatal(err)
	}
	state, err = s.LookupWork(ctx, claim.ID)
	if err != nil || state.State != "succeeded" || len(state.Payload) == 0 {
		t.Fatal("success payload lost", state, err)
	}
	if count(t, admin, "attempts") != 2 {
		t.Fatal("attempt history lost")
	}
}

func TestPostgresExplicitReconciliationAndRenewal(t *testing.T) {
	admin, c := integration(t)
	reset(t, admin)
	s := runtimeStore(t, admin, c)
	ctx := context.Background()
	if err := s.Reserve(ctx, "reconcile", "commands", json.RawMessage(`{"device":"one"}`)); err != nil {
		t.Fatal(err)
	}
	claim, err := s.Claim(ctx, "commands", "worker", time.Minute)
	if err != nil || claim == nil {
		t.Fatal(err)
	}
	if err = s.StartAttempt(ctx, *claim); err != nil {
		t.Fatal(err)
	}
	if err = s.Renew(ctx, *claim, 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err = s.FinishAttempt(ctx, *claim, jobs.Uncertain, json.RawMessage(`{"error":"lost_response"}`)); err != nil {
		t.Fatal(err)
	}
	if err = s.ReconcileSuccess(ctx, claim.ID, claim.Generation, json.RawMessage(`{"verified_command_id":"server-command"}`)); err != nil {
		t.Fatal(err)
	}
	state, err := s.LookupWork(ctx, claim.ID)
	if err != nil || state.State != "succeeded" {
		t.Fatal(state, err)
	}
	if count(t, admin, "reconciliations") != 1 || count(t, admin, "attempts") != 1 || count(t, admin, "quarantine") != 1 {
		t.Fatal("reconciliation destroyed history")
	}
	if err = s.Renew(ctx, *claim, time.Minute); !errors.Is(err, jobs.ErrFenced) {
		t.Fatal("terminal claim renewed", err)
	}
}
