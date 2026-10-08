package postgres

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestPostgresLegacyUsageExactIdempotentAndFenced(t *testing.T) {
	s, _ := integration(t)
	reset(t, s)
	ctx := context.Background()
	id := strings.Repeat("b", 64)
	hash := strings.Repeat("a", 64)
	_, err := s.pool.Exec(ctx, "TRUNCATE bootstrap_private.writer_fences,bootstrap_private.worker_fences,bootstrap_private.legacy_usage,bootstrap_private.transitions CASCADE")
	if err != nil {
		t.Fatal(err)
	}
	input := []byte(`{"version":1,"tracker":{"version":1,"sessions":[{"key":["192.0.2.1","10.0.0.1","aabbccddeeff","session"],"duration":42,"upload":18446744073709551615,"download":3,"stopped":true,"display":{"host":"radius-primary"},"identity":null,"last_seen":1728000000.125}]},"through":1728000001.25,"pending":[],"uncertain":false,"seeded":true,"preview_id":null}`)
	if _, err = s.ImportLegacyUsage(ctx, id, input, []string{"radius-primary", "radius-secondary"}); err == nil {
		t.Fatal("unfenced import allowed")
	}
	gate := MaintenanceGate{Store: s}
	for _, node := range []string{"radius-primary", "radius-secondary"} {
		if err = gate.With(ctx, "fence", func(ctx context.Context) error { return s.RecordWriterFence(ctx, id, node, hash, hash) }); err != nil {
			t.Fatal(err)
		}
	}
	imported, err := s.ImportLegacyUsage(ctx, id, input, []string{"radius-primary", "radius-secondary"})
	if err != nil || !imported {
		t.Fatal(err)
	}
	imported, err = s.ImportLegacyUsage(ctx, id, input, []string{"radius-primary", "radius-secondary"})
	if err != nil || imported {
		t.Fatal("reimport changed state", err)
	}
	if _, err = s.ImportLegacyUsage(ctx, id, bytes.Replace(input, []byte(`"duration":42`), []byte(`"duration":43`), 1), []string{"radius-primary", "radius-secondary"}); err == nil {
		t.Fatal("changed checksum allowed")
	}
	var upload string
	var bits int
	var stopped bool
	if err = s.pool.QueryRow(ctx, `SELECT upload::text,bits,stopped FROM ledger.sessions`).Scan(&upload, &bits, &stopped); err != nil || upload != "18446744073709551615" || bits != 64 || !stopped {
		t.Fatal("lossy session import", err)
	}
	if _, err = s.ExportLegacyUsage(ctx, id); err == nil {
		t.Fatal("export before worker fencing")
	}
	if err = s.BlockTransition(ctx, id); err != nil {
		t.Fatal(err)
	}
	for _, node := range []string{"radius-primary", "radius-secondary"} {
		if err = gate.With(ctx, "new-fence", func(ctx context.Context) error { return s.RecordWorkerFence(ctx, id, node, hash) }); err != nil {
			t.Fatal(err)
		}
	}
	out, err := s.ExportLegacyUsage(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte("18446744073709551615")) || !bytes.Contains(out, []byte("1728000000.125")) {
		t.Fatal("lossy export", string(out))
	}
	if count(t, s, "auth_cursors") != 0 {
		t.Fatal("DD read highwater became native spool cursor")
	}
}
