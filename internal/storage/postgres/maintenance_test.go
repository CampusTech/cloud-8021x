package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/stepca"
)

func TestMaintenanceUncertainBlocksLaterNodes(t *testing.T) {
	s, _ := integration(t)
	ctx := context.Background()
	if e := s.Migrate(ctx, Roles{Runtime: "app_runtime", Native: "app_native"}); e != nil {
		t.Fatal(e)
	}
	g := MaintenanceGate{Store: s, Lease: time.Second}
	called := 0
	e := g.With(ctx, "test-maintenance", func(context.Context) error { called++; return errors.New("ambiguous publication") })
	if e == nil {
		t.Fatal("uncertainty lost")
	}
	e = g.With(ctx, "other-node", func(context.Context) error { called++; return nil })
	if e == nil || called != 1 {
		t.Fatal("uncertain operation allowed overlap")
	}
}

func TestMaintenancePrivateStateAndLostFence(t *testing.T) {
	s, c := integration(t)
	ctx := context.Background()
	if _, e := s.pool.Exec(ctx, "TRUNCATE bootstrap_private.maintenance CASCADE"); e != nil {
		t.Fatal(e)
	}
	runtime := runtimeStore(t, s, c)
	if _, e := runtime.pool.Exec(ctx, "UPDATE bootstrap_private.maintenance SET outcome='complete'"); e == nil {
		t.Fatal("runtime mutated root maintenance")
	}
	gate := MaintenanceGate{Store: s, Lease: time.Second}
	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- gate.With(ctx, "first-node", func(ctx context.Context) error { close(started); <-ctx.Done(); return ctx.Err() })
	}()
	<-started
	if e := gate.With(ctx, "second-node", func(context.Context) error { t.Error("overlapping maintenance"); return nil }); e == nil {
		t.Fatal("overlap accepted")
	}
	if _, e := s.pool.Exec(ctx, "UPDATE bootstrap_private.maintenance SET expires_at=clock_timestamp()-interval '1 second' WHERE outcome='started'"); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-result:
		if e == nil {
			t.Fatal("lost fence reported success")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("lost fence did not cancel external operation")
	}
	if e := gate.With(ctx, "replacement", func(context.Context) error { t.Error("expired work was reclaimed"); return nil }); e == nil {
		t.Fatal("expiration cleared uncertainty")
	}
	var id int64
	if e := s.pool.QueryRow(ctx, "SELECT max(id) FROM bootstrap_private.maintenance").Scan(&id); e != nil {
		t.Fatal(e)
	}
	if e := s.ReconcileMaintenance(ctx, id, func(context.Context, MaintenanceEvidence) error { return errors.New("no evidence") }); e == nil {
		t.Fatal("reconciliation accepted absent evidence")
	}
	if e := s.ReconcileMaintenance(ctx, id, func(_ context.Context, evidence MaintenanceEvidence) error {
		if evidence.Operation != "first-node" {
			t.Fatal(evidence)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e := gate.With(ctx, "after-reviewed-reconciliation", func(context.Context) error { return nil }); e != nil {
		t.Fatal(e)
	}
}

func TestMaintenanceNestedScopeAndCAJournal(t *testing.T) {
	s, c := integration(t)
	ctx := context.Background()
	if e := s.Migrate(ctx, Roles{Runtime: "app_runtime", Native: "app_native"}); e != nil {
		t.Fatal(e)
	}
	if _, e := s.pool.Exec(ctx, "TRUNCATE bootstrap_private.maintenance, bootstrap_private.ca_publication CASCADE"); e != nil {
		t.Fatal(e)
	}
	gate := MaintenanceGate{Store: s, Lease: time.Second}
	var escaped context.Context
	if e := gate.With(ctx, "outer", func(ctx context.Context) error {
		escaped = ctx
		return gate.With(ctx, "inner", func(ctx context.Context) error { return ctx.Err() })
	}); e != nil {
		t.Fatal(e)
	}
	if e := gate.With(escaped, "escaped", func(context.Context) error { t.Error("expired scope reused"); return nil }); e == nil {
		t.Fatal("escaped scope accepted")
	}
	journal := CAJournal{Store: s}
	ref := strings.Repeat("a", 64)
	data := stepca.Publication{Secret: "projects/fixture-project/secrets/stage", SHA256: strings.Repeat("b", 64)}
	if e := journal.Begin(ctx, ref, data); e != nil {
		t.Fatal(e)
	}
	if e := journal.Begin(ctx, ref, stepca.Publication{Secret: data.Secret, SHA256: strings.Repeat("c", 64)}); e == nil {
		t.Fatal("replaced immutable material")
	}
	got, e := journal.Load(ctx, ref)
	if e != nil || got != data {
		t.Fatalf("journal read %v", e)
	}
	if e := journal.Bind(ctx, ref, data.Secret+"/versions/1"); e != nil {
		t.Fatal(e)
	}
	if e := journal.Published(ctx, ref); e != nil {
		t.Fatal(e)
	}
	got, e = journal.Load(ctx, ref)
	if e != nil || !got.Published {
		t.Fatal("readiness not durable")
	}
	runtime := runtimeStore(t, s, c)
	if _, e := (CAJournal{Store: runtime}).Load(ctx, ref); e == nil {
		t.Fatal("runtime read CA private material")
	}
	if _, e := runtime.pool.Exec(ctx, "DELETE FROM bootstrap_private.ca_publication"); e == nil {
		t.Fatal("runtime deleted CA material")
	}
}

func TestInstallationJournalContainsOnlyReferenceAndRejectsSecretBytes(t *testing.T) {
	s, c := integration(t)
	ctx := context.Background()
	if _, e := s.pool.Exec(ctx, "TRUNCATE bootstrap_private.maintenance CASCADE"); e != nil {
		t.Fatal(e)
	}
	const sentinel = "PRIVATE_KEY_RADIUS_SQL_FLEET_SENTINEL"
	reference := strings.Repeat("e", 32)
	if e := s.RecordInstallation(ctx, reference); e == nil {
		t.Fatal("unowned reference accepted")
	}
	if e := (MaintenanceGate{Store: s}).With(ctx, "bootstrap", func(ctx context.Context) error {
		if e := s.RecordInstallation(ctx, `{"Data":"`+sentinel+`"}`); e == nil {
			t.Fatal("serialized file bytes accepted")
		}
		if e := s.RecordInstallation(ctx, reference); e != nil {
			return e
		}
		if e := s.RecordInstallation(ctx, strings.Repeat("f", 32)); e == nil {
			t.Fatal("receipt reference replaced")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	var metadata string
	if e := s.pool.QueryRow(ctx, "SELECT row_to_json(m)::text FROM bootstrap_private.maintenance m").Scan(&metadata); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(metadata, sentinel) || !strings.Contains(metadata, reference) || strings.Contains(metadata, `"Files"`) {
		t.Fatal("private material entered SQL journal")
	}
	for _, role := range []string{"app_runtime", "app_native"} {
		password := "disposable-runtime"
		if role == "app_native" {
			password = "disposable-native"
		}
		restricted := roleStore(t, c, role, password)
		if _, e := restricted.pool.Exec(ctx, "SELECT installation FROM bootstrap_private.maintenance"); e == nil {
			t.Fatal("nonroot read installation journal", role)
		}
	}
}

func TestBootstrapPreservesCAIsolation(t *testing.T) {
	s, _ := integration(t)
	ctx := context.Background()
	roles := Roles{Runtime: "app_runtime", Native: "app_native"}
	if e := s.CheckCAIsolation(ctx, roles); e == nil {
		t.Fatal("accepted missing CA database pair")
	}
	for _, q := range []string{"CREATE ROLE stepca LOGIN", "CREATE DATABASE stepca OWNER stepca", "CREATE DATABASE stepca_rsa OWNER stepca", "REVOKE ALL ON DATABASE stepca,stepca_rsa FROM PUBLIC"} {
		if _, e := s.pool.Exec(ctx, q); e != nil {
			t.Fatal(e)
		}
	}
	if e := s.CheckCAIsolation(ctx, roles); e != nil {
		t.Fatal(e)
	}
	for _, priv := range []string{"CONNECT", "TEMP"} {
		if _, e := s.pool.Exec(ctx, "GRANT "+priv+" ON DATABASE stepca TO app_runtime"); e != nil {
			t.Fatal(e)
		}
		if e := s.CheckCAIsolation(ctx, roles); e == nil {
			t.Fatal("accepted application CA privilege", priv)
		}
		if _, e := s.pool.Exec(ctx, "REVOKE "+priv+" ON DATABASE stepca FROM app_runtime"); e != nil {
			t.Fatal(e)
		}
	}
	if e := s.CheckCAIsolation(ctx, roles); e != nil {
		t.Fatal(e)
	}
}

func TestSourceRetentionQueryKeepsUnresolvedPayloadsWithoutRefreshingTime(t *testing.T) {
	s, _ := integration(t)
	ctx := context.Background()
	reset(t, s)
	for _, state := range []string{"pending", "leased", "started", "quarantine", "succeeded"} {
		if e := s.Reserve(ctx, state, "sources:radius-primary", []byte(`{"observed_at":"2000-01-01T00:00:00Z","state":"`+state+`"}`)); e != nil {
			t.Fatal(e)
		}
		if _, e := s.pool.Exec(ctx, "UPDATE ledger.work SET state=$2,updated_at='2000-01-01' WHERE id=$1", state, state); e != nil {
			t.Fatal(e)
		}
	}
	got, e := s.UnresolvedSourcePayloads(ctx, "radius-primary")
	if e != nil || len(got) != 4 {
		t.Fatal("unresolved proof omitted", e, len(got))
	}
	var unchanged bool
	if e := s.pool.QueryRow(ctx, "SELECT bool_and(updated_at='2000-01-01'::timestamptz) FROM ledger.work").Scan(&unchanged); e != nil || !unchanged {
		t.Fatal("retention refreshed original state", e)
	}
	if _, e := s.UnresolvedSourcePayloads(ctx, "other"); e == nil {
		t.Fatal("unbound node accepted")
	}
	if _, e := s.pool.Exec(ctx, `INSERT INTO ledger.work(id,kind,payload) SELECT 'bound-'||n,'sources:radius-secondary','{}'::jsonb FROM generate_series(1,1025) n`); e != nil {
		t.Fatal(e)
	}
	if _, e := s.UnresolvedSourcePayloads(ctx, "radius-secondary"); e == nil {
		t.Fatal("unbounded proof list accepted")
	}
}
