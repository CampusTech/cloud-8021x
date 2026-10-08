package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/jobs"
)

func TestPostgresSourceNodeSerializationAndUncertainty(t *testing.T) {
	admin, c := integration(t)
	reset(t, admin)
	a := runtimeStore(t, admin, c)
	b := runtimeStore(t, admin, c)
	ctx := context.Background()
	for _, row := range []struct{ id, node string }{{"revision-a", "radius-primary"}, {"revision-b", "radius-primary"}, {"secondary-a", "radius-secondary"}} {
		payload, _ := json.Marshal(map[string]string{"node": row.node, "candidate": row.id})
		if e := a.Reserve(ctx, row.id, "sources:"+row.node, payload); e != nil {
			t.Fatal(e)
		}
	}
	var wg sync.WaitGroup
	results := make(chan *jobs.Claim, 2)
	errs := make(chan error, 2)
	for _, store := range []*Store{a, b} {
		wg.Go(func() {
			claim, e := store.ClaimSource(ctx, "radius-primary", "worker", time.Minute)
			results <- claim
			errs <- e
		})
	}
	wg.Wait()
	close(results)
	var held *jobs.Claim
	count := 0
	for claim := range results {
		if claim != nil {
			count++
			held = claim
		}
	}
	for range 2 {
		if e := <-errs; e != nil {
			t.Fatal(e)
		}
	}
	if count != 1 {
		t.Fatalf("same node admitted %d workers", count)
	}
	if _, e := a.Claim(ctx, "sources:radius-primary", "bypass", time.Minute); e == nil {
		t.Fatal("generic claim bypassed source guard")
	}
	secondary, e := b.ClaimSource(ctx, "radius-secondary", "other", time.Minute)
	if e != nil || secondary == nil {
		t.Fatal("independent node blocked", e)
	}
	if e = a.StartAttempt(ctx, *held); e != nil {
		t.Fatal(e)
	}
	if claim, e := b.ClaimSource(ctx, "radius-primary", "next", time.Minute); e != nil || claim != nil {
		t.Fatal("new revision bypassed started attempt", e)
	}
	if _, e = admin.pool.Exec(ctx, "UPDATE ledger.work SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1", held.ID); e != nil {
		t.Fatal(e)
	}
	if claim, e := b.ClaimSource(ctx, "radius-primary", "next", time.Minute); e != nil || claim != nil {
		t.Fatal("expired uncertain attempt bypassed", e)
	}
	state, e := a.LookupWork(ctx, held.ID)
	if e != nil || state.State != "quarantine" || len(state.Payload) == 0 {
		t.Fatal("uncertainty lost", state, e)
	}
	if e = a.FinishAttempt(ctx, *held, jobs.Succeeded, json.RawMessage(`{}`)); !errors.Is(e, jobs.ErrFenced) {
		t.Fatal("expired finish accepted", e)
	}
	if e = a.ReconcileSuccess(ctx, held.ID, held.Generation, json.RawMessage(`{"fixed_node":"radius-primary","verified_actual_desired_state":true,"fixture":true}`)); e != nil {
		t.Fatal(e)
	}
	next, e := b.ClaimSource(ctx, "radius-primary", "next", time.Minute)
	if e != nil || next == nil || next.ID == held.ID {
		t.Fatal("reconciliation did not release next revision", next, e)
	}
	if string(next.Payload) == string(held.Payload) {
		t.Fatal("claimed payload replaced by current caller")
	}
}
func TestPostgresSourceExpiredUnstartedGeneration(t *testing.T) {
	admin, c := integration(t)
	reset(t, admin)
	s := runtimeStore(t, admin, c)
	ctx := context.Background()
	if e := s.Reserve(ctx, "source-old", "sources:radius-primary", json.RawMessage(`{"node":"radius-primary"}`)); e != nil {
		t.Fatal(e)
	}
	old, e := s.ClaimSource(ctx, "radius-primary", "old", time.Minute)
	if e != nil || old == nil {
		t.Fatal(e)
	}
	if _, e = admin.pool.Exec(ctx, "UPDATE ledger.work SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1", old.ID); e != nil {
		t.Fatal(e)
	}
	current, e := s.ClaimSource(ctx, "radius-primary", "new", time.Minute)
	if e != nil || current == nil || current.Generation != old.Generation+1 {
		t.Fatal("unstarted claim not recovered", current, e)
	}
	if e = s.StartAttempt(ctx, *old); !errors.Is(e, jobs.ErrFenced) {
		t.Fatal("old generation started", e)
	}
}

func TestPostgresHistoricalSourceRecoveryRequiresProtectedExactQuarantine(t *testing.T) {
	s, c := integration(t)
	reset(t, s)
	ctx := context.Background()
	runtime := runtimeStore(t, s, c)
	if _, e := s.pool.Exec(ctx, "TRUNCATE bootstrap_private.maintenance,bootstrap_private.transitions CASCADE"); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(context.Background(), "TRUNCATE bootstrap_private.maintenance CASCADE") })
	transition := strings.Repeat("c", 64)
	if _, e := s.pool.Exec(ctx, `INSERT INTO bootstrap_private.transitions(id,enabled) VALUES($1,true)`, transition); e != nil {
		t.Fatal(e)
	}
	if _, e := s.pool.Exec(ctx, `INSERT INTO bootstrap_private.writer_fences(transition,node,config_sha256,receipt_sha256) VALUES($1,'radius-primary',$1,$1),($1,'radius-secondary',$1,$1)`, transition); e != nil {
		t.Fatal(e)
	}
	payload := json.RawMessage(`{"node":"radius-primary","candidate":[]}`)
	if e := runtime.Reserve(ctx, "sources:fixture", "sources:radius-primary", payload); e != nil {
		t.Fatal(e)
	}
	claim, e := runtime.ClaimSource(ctx, "radius-primary", "fixture", time.Minute)
	if e != nil || claim == nil {
		t.Fatal(claim, e)
	}
	if e = runtime.StartAttempt(ctx, *claim); e != nil {
		t.Fatal(e)
	}
	if e = runtime.FinishAttempt(ctx, *claim, jobs.Uncertain, json.RawMessage(`{}`)); e != nil {
		t.Fatal(e)
	}
	calls := 0
	verify := func(context.Context, json.RawMessage) (json.RawMessage, error) {
		calls++
		return json.RawMessage(`{"historical":true,"original_timestamp":1}`), nil
	}
	if e = runtime.ReconcileHistoricalSource(ctx, strings.Repeat("c", 64), "radius-primary", claim.ID, claim.Generation, verify); e == nil || calls != 0 {
		t.Fatal("unprotected reconciliation", e, calls)
	}
	gate := MaintenanceGate{Store: s}
	if e = gate.With(ctx, "source-historical", func(ctx context.Context) error {
		return s.ReconcileHistoricalSource(ctx, strings.Repeat("c", 64), "radius-primary", claim.ID, claim.Generation, verify)
	}); e != nil {
		t.Fatal(e)
	}
	state, e := s.LookupWork(ctx, claim.ID)
	if e != nil || state.State != "succeeded" || calls != 1 {
		t.Fatal(state, e, calls)
	}
	// Tuple mismatch is read-only failure before the evidence verifier.
	calls = 0
	if e = gate.With(ctx, "source-historical-wrong", func(ctx context.Context) error {
		return s.ReconcileHistoricalSource(ctx, strings.Repeat("c", 64), "radius-secondary", claim.ID, claim.Generation, verify)
	}); e == nil || calls != 0 {
		t.Fatal("wrong node accepted", e, calls)
	}
}
