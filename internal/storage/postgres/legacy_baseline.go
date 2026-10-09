package postgres

import (
	"context"
	"errors"

	"github.com/CampusTech/cloud-8021x/internal/accounting"
	"github.com/CampusTech/cloud-8021x/internal/migration"
	"github.com/jackc/pgx/v5"
)

// Only a protected incomplete-v2 import installs a floor. Native receipt times
// cannot complete the old source scan. The first non-predating valid native
// observation at/after the original floor learns a baseline without crediting
// unobserved history; subsequent measured intervals retain ordinary semantics.
func gateLegacyBaseline(ctx context.Context, tx pgx.Tx, prior, next accounting.State, event accounting.Event, interval *accounting.Interval, reason string, required bool) (*accounting.Interval, string, bool, error) {
	var raw string
	err := tx.QueryRow(ctx, `SELECT credit_start FROM ledger.legacy_usage_floor WHERE singleton`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return interval, reason, required, nil
	}
	if err != nil {
		return nil, "", required, err
	}
	floor, err := migration.ReceiptTime([]byte(raw))
	if err != nil {
		return nil, "", required, err
	}
	if event.Received.Before(floor) {
		// A delayed pre-floor update can move counters under the existing
		// ordering rules. Re-arm the first-native barrier only when it did.
		advanced := !prior.Initialized || prior.Duration != next.Duration || prior.Upload != next.Upload || prior.Download != next.Download || prior.Bits != next.Bits
		return nil, "legacy_precredit_baseline", required || advanced, nil
	}
	if !required {
		return interval, reason, false, nil
	}
	accepted := reason == "baseline" || reason == "interval" || reason == "counter_reset" || reason == "precision_change" || (reason == "duplicate_or_reordered" && event.Duration == next.Duration && event.Upload == next.Upload && event.Download == next.Download)
	if accepted && !event.Received.Before(prior.LastSeen) {
		return nil, "legacy_native_baseline", false, nil
	}
	return nil, reason, true, nil
}
