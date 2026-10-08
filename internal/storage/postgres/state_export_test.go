package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/migration"
)

func TestPostgresColdExportRetainsCurrentStateAndUnknownNewWork(t *testing.T) {
	s, _ := integration(t)
	ctx := context.Background()
	if _, e := s.pool.Exec(ctx, "TRUNCATE bootstrap_private.maintenance,bootstrap_private.transitions,ledger.sessions,ledger.work,ledger.import_markers,ledger.auth_cursors CASCADE"); e != nil {
		t.Fatal(e)
	}
	id, hash := strings.Repeat("7", 64), strings.Repeat("a", 64)
	gate := MaintenanceGate{Store: s}
	for _, node := range []string{"radius-primary", "radius-secondary"} {
		if e := gate.With(ctx, "fixture-fence", func(ctx context.Context) error { return s.RecordWriterFence(ctx, id, node, hash, hash) }); e != nil {
			t.Fatal(e)
		}
	}
	usage := json.RawMessage(`{"version":1,"tracker":{"version":1,"sessions":[{"key":["192.0.2.1","10.0.0.1","aabbccddeeff","session"],"duration":42,"upload":18446744073709551615,"download":3,"stopped":true,"display":{"host":"radius-primary"},"identity":null,"last_seen":1728000000.123456789}]},"through":1728000001.25,"pending":[],"uncertain":false,"seeded":true,"preview_id":null}`)
	original := json.RawMessage(`{"version":2,"updated_at":1791453600.123456789,"identities":{"ambiguous":null},"certificates":{},"hardware_serials":{}}`)
	current := bytes.Replace(original, []byte("1791453600.123456789"), []byte("1791453700.999999999"), 1)
	for _, node := range []string{"radius-primary", "radius-secondary"} {
		b := migration.Bundle{Version: 1, Node: node, Policy: original, ClassKeySHA256: hash, Usage: usage, SQL: migration.LegacySQL{Status: "absent"}, FingerprintEnforced: true}
		raw, _ := json.Marshal(b)
		if e := gate.With(ctx, "fixture-import", func(ctx context.Context) error { _, e := s.ImportLegacyBundle(ctx, id, raw); return e }); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := s.pool.Exec(ctx, `INSERT INTO ledger.work(id,kind,payload,state,generation,owner) VALUES('unknown-delivery','outbox','{"event":"Acct-Usage","upload_delta_bytes":18446744073709551615,"received_at":"2026-10-08T10:00:00.123456789Z"}','started',7,'original-worker'); INSERT INTO ledger.attempts(work_id,generation,owner) VALUES('unknown-delivery',7,'original-worker'); INSERT INTO ledger.auth_cursors(source,cursor) VALUES('radius-primary/auth-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-2026100810.detail','123')`); e != nil {
		t.Fatal(e)
	}
	if e := s.BlockTransition(ctx, id); e != nil {
		t.Fatal(e)
	}
	if e := s.RequireWorkerExportReady(ctx, id); e == nil {
		t.Fatal("export ready without physical receipts")
	}
	var unresolved int
	if e := s.pool.QueryRow(ctx, "SELECT count(*) FROM bootstrap_private.maintenance WHERE outcome IN ('started','uncertain')").Scan(&unresolved); e != nil || unresolved != 0 {
		t.Fatal("read-only preflight poisoned recovery", e, unresolved)
	}
	for _, node := range []string{"radius-primary", "radius-secondary"} {
		state := migration.NodeState{Version: 1, Node: node, Inventory: current, ClassKeySHA256: hash, FingerprintEnforced: true, ProviderCaches: map[string]json.RawMessage{}}
		raw, _ := json.Marshal(state)
		if e := gate.With(ctx, "fixture-worker-fence", func(ctx context.Context) error { return s.RecordWorkerState(ctx, id, hash, raw) }); e != nil {
			t.Fatal(e)
		}
	}
	if e := s.RequireWorkerExportReady(ctx, id); e != nil {
		t.Fatal(e)
	}
	var data []byte
	if e := gate.With(ctx, "fixture-export", func(ctx context.Context) error { var e error; data, e = s.ExportState(ctx, id); return e }); e != nil {
		t.Fatal(e)
	}
	var out migration.RollbackExport
	if json.Unmarshal(data, &out) != nil || len(out.Current) != 2 || !out.WorkersBlocked || out.UsageAbsent || len(out.Ledger.Work) != 1 || len(out.Ledger.Attempts) != 1 || len(out.Ledger.AuthCursors) != 1 {
		t.Fatal("incomplete cold export")
	}
	if !bytes.Contains(out.Usage, []byte("18446744073709551615")) || !bytes.Contains(out.Usage, []byte("1728000000.123456789")) {
		t.Fatal("lost exact original counters or times")
	}
	if !bytes.Contains(out.Legacy["radius-primary"], []byte("1791453700.999999999")) {
		t.Fatal("exported stale initial authorization instead of current state")
	}
	if !bytes.Contains(out.Ledger.Work[0], []byte(`"state":"started"`)) || !bytes.Contains(out.Ledger.Work[0], []byte("18446744073709551615")) {
		t.Fatal("unknown new delivery altered", string(out.Ledger.Work[0]))
	}
	var state string
	if e := s.pool.QueryRow(ctx, `SELECT state FROM ledger.work WHERE id='unknown-delivery'`).Scan(&state); e != nil || state != "started" {
		t.Fatal("export changed unknown work", e)
	}
}
