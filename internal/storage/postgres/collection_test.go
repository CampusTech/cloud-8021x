package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/jobs"
	"github.com/CampusTech/cloud-8021x/migrations"
)

func TestPostgresCollectionCadenceBudgetAndUncertainty(t *testing.T) {
	admin, c := integration(t)
	reset(t, admin)
	a := runtimeStore(t, admin, c)
	b := runtimeStore(t, admin, c)
	ctx := context.Background()
	payload := json.RawMessage(`{"collection_key":"fixture-host","host_id":1,"command_uuid":"request-1"}`)
	var wg sync.WaitGroup
	accepted := make(chan bool, 2)
	errs := make(chan error, 2)
	for i, s := range []*Store{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := []string{"request-a", "request-b"}[i]
			ok, err := s.ReserveCollection(ctx, id, "fleet-test", "fixture-host", payload, time.Hour, 2)
			accepted <- ok
			errs <- err
		}()
	}
	wg.Wait()
	close(accepted)
	n := 0
	for ok := range accepted {
		if ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("cross worker cadence admitted %d", n)
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	claim, err := a.Claim(ctx, "fleet-test", "worker", time.Minute)
	if err != nil || claim == nil {
		t.Fatal(err)
	}
	if err = a.StartAttempt(ctx, *claim); err != nil {
		t.Fatal(err)
	}
	if err = a.FinishAttempt(ctx, *claim, jobs.Uncertain, json.RawMessage(`{"uncertain":true}`)); err != nil {
		t.Fatal(err)
	}
	// Advancing only the fixture's reservation age permits the second bounded slot.
	if _, err = admin.pool.Exec(ctx, "UPDATE ledger.work SET created_at=clock_timestamp()-interval '2 hours'"); err != nil {
		t.Fatal(err)
	}
	ok, err := b.ReserveCollection(ctx, "request-c", "fleet-test", "fixture-host", payload, time.Hour, 2)
	if err != nil || !ok {
		t.Fatalf("second slot %v %v", ok, err)
	}
	if _, err = admin.pool.Exec(ctx, "UPDATE ledger.work SET created_at=clock_timestamp()-interval '2 hours'"); err != nil {
		t.Fatal(err)
	}
	ok, err = b.ReserveCollection(ctx, "request-d", "fleet-test", "fixture-host", payload, time.Hour, 2)
	if err != nil || ok {
		t.Fatalf("uncertain slot was blindly freed %v %v", ok, err)
	}
	works, err := a.ListCollection(ctx, "fixture-host")
	if err != nil || len(works) != 2 {
		t.Fatalf("durable work %#v %v", works, err)
	}
}

func TestPostgresCollectionMigrationUpgradesV1AndUsesScopedIndexes(t *testing.T) {
	admin, c := integration(t)
	reset(t, admin)
	ctx := context.Background()
	// Recreate a genuine reviewed v1 database state without touching CA objects.
	_, err := admin.pool.Exec(ctx, "DROP INDEX IF EXISTS ledger.work_collection_recent; DROP INDEX IF EXISTS ledger.work_collection_pending; ALTER TABLE ledger.intake DROP COLUMN terminate_cause, DROP COLUMN terminate_cause_count; DELETE FROM ledger.schema_version WHERE version>1")
	if err != nil {
		t.Fatal(err)
	}
	if err = admin.Migrate(ctx, Roles{Runtime: "app_runtime", Native: "app_native"}); err != nil {
		t.Fatal(err)
	}
	runtime := runtimeStore(t, admin, c)
	var version int
	if err = runtime.pool.QueryRow(ctx, "SELECT max(version) FROM ledger.schema_version").Scan(&version); err != nil || version != migrations.Version {
		t.Fatalf("v1 collection migration not applied %d %v", version, err)
	}
	var indexes int
	if err = admin.pool.QueryRow(ctx, "SELECT count(*) FROM pg_indexes WHERE schemaname='ledger' AND indexname IN ('work_collection_recent','work_collection_pending')").Scan(&indexes); err != nil || indexes != 2 {
		t.Fatalf("collection scope indexes %d %v", indexes, err)
	}
}

func TestPostgresCollectionResultImmutableAndSubmissionRemainsPending(t *testing.T) {
	admin, c := integration(t)
	reset(t, admin)
	repository := runtimeStore(t, admin, c)
	ctx := context.Background()
	payload := json.RawMessage(`{"collection_key":"fixture-host","command_uuid":"command","host_id":1}`)
	for i, id := range []string{"one", "two", "three"} {
		ok, err := repository.ReserveCollection(ctx, id, "fleet-test", "fixture-host", payload, time.Hour, 2)
		if err != nil {
			t.Fatal(err)
		}
		if i == 2 {
			if ok {
				t.Fatal("successful pending POST dropped budget")
			}
			break
		}
		if !ok {
			t.Fatal("expected bounded slot")
		}
		claim, err := repository.Claim(ctx, "fleet-test", "worker", time.Minute)
		if err != nil || claim == nil {
			t.Fatal(err)
		}
		if err = repository.StartAttempt(ctx, *claim); err != nil {
			t.Fatal(err)
		}
		if err = repository.FinishAttempt(ctx, *claim, jobs.Succeeded, json.RawMessage(`{"pending":true}`)); err != nil {
			t.Fatal(err)
		}
		if _, err = admin.pool.Exec(ctx, "UPDATE ledger.work SET created_at=clock_timestamp()-interval '2 hours'"); err != nil {
			t.Fatal(err)
		}
	}
	evidence := json.RawMessage(`{"command_uuid":"command","host_id":1,"provenance_verified":true}`)
	first := json.RawMessage(`{"pending":false,"observation":{"ObservedAt":100}}`)
	if err := repository.RecordCollectionResult(ctx, "one", 1, first, evidence); err != nil {
		t.Fatal(err)
	}
	if err := repository.RecordCollectionResult(ctx, "one", 1, first, evidence); err != nil {
		t.Fatal("idempotent terminal proof", err)
	}
	if err := repository.RecordCollectionResult(ctx, "one", 1, json.RawMessage(`{"pending":false,"observation":{"ObservedAt":200}}`), evidence); !errors.Is(err, jobs.ErrConflict) {
		t.Fatalf("terminal result freshened/replaced %v", err)
	}
	if count(t, admin, "reconciliations") != 1 {
		t.Fatal("replayed evidence duplicated reconciliation")
	}
}
