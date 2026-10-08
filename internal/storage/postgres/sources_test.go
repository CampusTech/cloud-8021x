package postgres

import (
	"context"
	"encoding/json"
	"errors"
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
