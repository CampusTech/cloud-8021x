package postgres

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting"
)

func TestPostgresIncompleteLegacyBaselineNativeCreditAndExactExport(t *testing.T) {
	admin, config := integration(t)
	reset(t, admin)
	ctx := context.Background()
	id, hash := strings.Repeat("b", 64), strings.Repeat("a", 64)
	if _, err := admin.pool.Exec(ctx, "TRUNCATE bootstrap_private.transitions CASCADE"); err != nil {
		t.Fatal(err)
	}
	gate := MaintenanceGate{Store: admin}
	for _, node := range []string{"radius-primary", "radius-secondary"} {
		if err := gate.With(ctx, "fence", func(ctx context.Context) error { return admin.RecordWriterFence(ctx, id, node, hash, hash) }); err != nil {
			t.Fatal(err)
		}
	}
	original := []byte(`{"version":2,"phase":"baseline","tracker":{"version":1,"sessions":[{"key":["192.0.2.1","192.0.2.2","aabbccddeeff","baseline"],"duration":10,"upload":100,"download":200,"stopped":false,"display":{},"identity":null,"last_seen":1799999980} ]},"through":1799999990,"credit_start":1800000000,"pending":[],"uncertain":false,"seeded":false,"preview_id":null}`)
	if imported, err := admin.ImportLegacyUsage(ctx, id, original, []string{"radius-primary", "radius-secondary"}); err != nil || !imported {
		t.Fatal(imported, err)
	}
	app := runtimeStore(t, admin, config)
	native := roleStore(t, config, "app_native", "disposable-native")
	// All receipts are original NAS receipt times, not processing clock or DD cursor.
	for _, item := range []struct {
		session          string
		offset           int64
		duration, upload int
		intervals        int
	}{
		{"baseline", -30, 5, 50, 0},                      // predating/reordered evidence cannot establish a native baseline
		{"baseline", -5, 20, 200, 0},                     // pre-floor report advances only baseline
		{"baseline", 0, 30, 300, 0},                      // first native observation at floor learns without historical delta
		{"baseline", 1, 40, 350, 1},                      // subsequent measured interval credits normally
		{"baseline", 2, 40, 350, 1},                      // semantic duplicate cannot reopen baseline
		{"new", -2, 10, 100, 1}, {"new", -1, 20, 200, 1}, // unseen pre-floor session also gates credit
		{"new", 0, 30, 300, 1}, {"new", 1, 40, 350, 2},
		{"baseline", -1, 50, 400, 2}, // delayed pre-floor advancement cannot anchor a credited interval
		{"baseline", 3, 60, 500, 2},
		{"baseline", 4, 70, 550, 3},
	} {
		r := testRaw(item.session, "Interim-Update")
		r.Received = time.Unix(1800000000+item.offset, 0)
		r.Duration = accounting.Attribute{Value: fmt.Sprint(item.duration), Count: 1}
		r.Input = accounting.Attribute{Value: fmt.Sprint(item.upload), Count: 1}
		r.Output = accounting.Attribute{Value: fmt.Sprint(item.upload * 2), Count: 1}
		if err := insertRaw(ctx, native, r); err != nil {
			t.Fatal(err)
		}
		if err := drain(ctx, app); err != nil {
			t.Fatal(err)
		}
		if n := count(t, admin, "intervals"); n != item.intervals {
			t.Fatalf("%s receipt offset%d: got %d intervals, want%d", item.session, item.offset, n, item.intervals)
		}
	}
	var total string
	if err := admin.pool.QueryRow(ctx, "SELECT sum(upload)::text FROM ledger.intervals").Scan(&total); err != nil || total != "150" {
		t.Fatal("unobserved historical delta credited", total, err)
	}
	if err := admin.BlockTransition(ctx, id); err != nil {
		t.Fatal(err)
	}
	for _, node := range []string{"radius-primary", "radius-secondary"} {
		if err := gate.With(ctx, "new-fence", func(ctx context.Context) error { return admin.RecordWorkerFence(ctx, id, node, hash) }); err != nil {
			t.Fatal(err)
		}
	}
	out, err := admin.ExportLegacyUsage(ctx, id)
	if err != nil || !bytes.Equal(out, original) {
		t.Fatalf("incomplete baseline must remain exact original, independent from native ledger: %s %v", out, err)
	}
	var up string
	if err := admin.pool.QueryRow(ctx, "SELECT upload::text FROM ledger.sessions WHERE session_key LIKE '%baseline%'").Scan(&up); err != nil || up != "550" {
		t.Fatal("current ledger disappeared", up, err)
	}
}
