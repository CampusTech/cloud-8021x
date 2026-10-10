package postgres

import (
	"context"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
)

func TestPostgresNativeAccountingIndependentOfLegacyState(t *testing.T) {
	admin, c := integration(t)
	reset(t, admin)
	ctx := context.Background()
	native := roleStore(t, c, "app_native", "disposable-native")
	for _, status := range []string{"Start", "Interim-Update"} {
		if err := insertRaw(ctx, native, testRaw("fresh-accounting", status)); err != nil {
			t.Fatal(err)
		}
	}

	// The fresh daemon must process standard native accounting without any
	// historical import evidence. Keep the fixture change inside this rollback.
	tx, err := admin.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	for _, query := range []string{
		"DROP TABLE IF EXISTS ledger.legacy_usage_floor",
		"ALTER TABLE ledger.sessions DROP COLUMN IF EXISTS native_baseline_required",
	} {
		if _, err = tx.Exec(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []string{"baseline", "interval"} {
		result, err := processLocked(ctx, tx, testKey, binding.MaxAge)
		if err != nil || !result.Processed || result.Reason != want {
			t.Fatalf("native accounting requires legacy state: result=%+v err=%v, want %s", result, err, want)
		}
	}
	var upload, download, seconds string
	if err = tx.QueryRow(ctx, "SELECT upload::text,download::text,seconds::text FROM ledger.intervals").Scan(&upload, &download, &seconds); err != nil || upload != "100" || download != "200" || seconds != "10" {
		t.Fatal("native measured interval changed", upload, download, seconds, err)
	}
	var observations, intervals, work int
	if err = tx.QueryRow(ctx, "SELECT (SELECT count(*) FROM ledger.observations),(SELECT count(*) FROM ledger.intervals),(SELECT count(*) FROM ledger.work)").Scan(&observations, &intervals, &work); err != nil || observations != 2 || intervals != 1 || work != 3 {
		t.Fatal("native accounting did not atomically queue its measured events", observations, intervals, work, err)
	}
}
