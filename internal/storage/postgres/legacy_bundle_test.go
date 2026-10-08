package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/migration"
)

func TestPostgresWholeBundleAtomicPublicationAndPendingGuards(t *testing.T) {
	s, c := integration(t)
	ctx := context.Background()
	id, hash := strings.Repeat("4", 64), strings.Repeat("a", 64)
	if _, e := s.pool.Exec(ctx, "TRUNCATE bootstrap_private.maintenance,bootstrap_private.transitions,ledger.legacy_collection_guards,ledger.sessions,ledger.work,ledger.import_markers CASCADE"); e != nil {
		t.Fatal(e)
	}
	gate := MaintenanceGate{Store: s}
	for _, node := range []string{"radius-primary", "radius-secondary"} {
		if e := gate.With(ctx, "state-fence", func(ctx context.Context) error { return s.RecordWriterFence(ctx, id, node, hash, hash) }); e != nil {
			t.Fatal(e)
		}
	}
	b := migration.Bundle{Version: 1, Node: "radius-primary", Policy: json.RawMessage(`{"version":2,"updated_at":1791453600.123456789,"identities":{"ambiguous":null},"certificates":{},"hardware_serials":{}}`), ClassKeySHA256: hash, FingerprintEnforced: true, Usage: json.RawMessage(`{"version":1,"tracker":{"version":1,"sessions":[]},"through":null,"pending":[],"uncertain":false,"seeded":false,"preview_id":null}`), SQL: migration.LegacySQL{Status: "absent"}, Certificates: json.RawMessage(`{"version":1,"source":"https://fleet.example.invalid","trust":null,"hosts":{"host":{"binding":[1,1791450000.125,null],"last_attempt":1791450010.25,"platform":"darwin"}},"commands":[{"uuid":"original-command","created_at":1791450010.25,"hosts":{"host":[1,1791450000.125,null]}}]}`)}
	bad := b
	bad.Discovery = json.RawMessage(`{"updated_at":null,"sources":{},"host_ids":{}}`)
	raw, _ := json.Marshal(bad)
	// Validation runs before any private gate callback or SQL state mutation.
	if _, e := s.ImportLegacyBundle(ctx, id, raw); e == nil {
		t.Fatal("late invalid component accepted")
	}
	var n int
	if e := s.pool.QueryRow(ctx, `SELECT count(*) FROM bootstrap_private.legacy_bundles`).Scan(&n); e != nil || n != 0 {
		t.Fatal("partial bundle", n, e)
	}
	for _, node := range []string{"radius-primary", "radius-secondary"} {
		b.Node = node
		raw, _ = json.Marshal(b)
		if e := gate.With(ctx, "state-migrate", func(ctx context.Context) error {
			changed, e := s.ImportLegacyBundle(ctx, id, raw)
			if e != nil {
				return e
			}
			if !changed {
				t.Fatal("first import not applied")
			}
			changed, e = s.ImportLegacyBundle(ctx, id, raw)
			if e != nil || changed {
				t.Fatal("same bundle not idempotent", e)
			}
			return s.ConfirmLegacyPublication(ctx, id, node, bundleDigest(raw))
		}); e != nil {
			t.Fatal(e)
		}
		if node == "radius-primary" && s.EnableImportedTransition(ctx, id) == nil {
			t.Fatal("one local publication enabled workers")
		}
	}
	if e := s.EnableImportedTransition(ctx, id); e != nil {
		t.Fatal(e)
	}
	runtime := runtimeStore(t, s, c).ForTransition(id)
	scope := migration.LegacyCollectionScope("https://fleet.example.invalid", 1, "host")
	payload, _ := json.Marshal(map[string]string{"collection_key": "new-format-key", "legacy_scope": scope})
	if changed, e := runtime.ReserveCollection(ctx, "new-request", "fleet-cert", "new-format-key", payload, time.Hour, 2); e != nil || changed {
		t.Fatal("legacy reservation did not block duplicate", changed, e)
	}
	if _, e := runtime.pool.Exec(ctx, `UPDATE ledger.legacy_collection_guards SET state='resolved'`); e == nil {
		t.Fatal("runtime released protected legacy guard")
	}
}

func TestPostgresResumeStatePublicationUsesExactCommittedOriginal(t *testing.T) {
	s, _ := integration(t)
	ctx := context.Background()
	if _, e := s.pool.Exec(ctx, "TRUNCATE bootstrap_private.maintenance,bootstrap_private.transitions,ledger.import_markers CASCADE"); e != nil {
		t.Fatal(e)
	}
	id, hash := strings.Repeat("e", 64), strings.Repeat("a", 64)
	gate := MaintenanceGate{Store: s}
	for _, node := range []string{"radius-primary", "radius-secondary"} {
		if e := gate.With(ctx, "fixture-fence", func(ctx context.Context) error { return s.RecordWriterFence(ctx, id, node, hash, hash) }); e != nil {
			t.Fatal(e)
		}
	}
	b := migration.Bundle{Version: 1, Node: "radius-primary", Policy: json.RawMessage(`{"version":2,"updated_at":1791453600.123456789,"identities":{},"certificates":{},"hardware_serials":{}}`), ClassKeySHA256: hash, UsageAbsent: true, SQL: migration.LegacySQL{Status: "absent"}}
	raw, _ := json.Marshal(b)
	identity := StatePublicationIdentity{WriterFenceIdentity: WriterFenceIdentity{Transition: id, Node: b.Node, ConfigSHA256: hash}, BundleSHA256: bundleDigest(raw)}
	operation, _ := identity.Operation()
	var attempt int64
	if e := gate.With(ctx, operation, func(ctx context.Context) error {
		var e error
		attempt, e = s.StatePublicationAttempt(ctx, identity)
		if e != nil {
			return e
		}
		if _, e = s.ImportLegacyBundle(ctx, id, raw); e != nil {
			return e
		}
		return errors.New("interrupted after commit before publication")
	}); e == nil {
		t.Fatal("missing interrupted operation")
	}
	called := false
	resume := func(ctx context.Context) error {
		called = true
		if e := s.ConfirmLegacyPublication(ctx, id, b.Node, identity.BundleSHA256); e != nil {
			return e
		}
		enabled, e := s.EnableIfPublished(ctx, id)
		if enabled {
			t.Fatal("single publication enabled workers")
		}
		return e
	}
	if e := s.ResumeStatePublication(ctx, attempt, identity, resume); e == nil || called {
		t.Fatal("resumed live attempt")
	}
	if _, e := s.pool.Exec(ctx, `UPDATE bootstrap_private.maintenance SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, attempt); e != nil {
		t.Fatal(e)
	}
	wrong := identity
	wrong.BundleSHA256 = strings.Repeat("b", 64)
	if e := s.ResumeStatePublication(ctx, attempt, wrong, resume); e == nil || called {
		t.Fatal("changed bundle resumed")
	}
	if e := s.ResumeStatePublication(ctx, attempt, identity, resume); e != nil || !called {
		t.Fatal("exact continuation failed", e)
	}
	var n int
	if e := s.pool.QueryRow(ctx, `SELECT count(*) FROM bootstrap_private.maintenance_recoveries WHERE attempt=$1 AND operation=$2`, attempt, operation).Scan(&n); e != nil || n != 1 {
		t.Fatal("recovery evidence missing", n, e)
	}
	var stored []byte
	if e := s.pool.QueryRow(ctx, `SELECT document FROM bootstrap_private.legacy_bundles WHERE transition=$1 AND node=$2`, id, b.Node).Scan(&stored); e != nil || !bytes.Equal(stored, raw) {
		t.Fatal("original bundle changed", e)
	}
}
