package postgres

import (
	"context"
)

// DeliveryHealth is a point-in-time shared-ledger observation. Nil ages mean no
// observation exists, not healthy freshness. Raw payloads and DSNs never escape.
type DeliveryHealth struct {
	Sessions, Intake, Quarantined, Outbox int64
	OutboxOldestAge, UsageAge             *float64
}

func (s *Store) ObserveDelivery(ctx context.Context) (DeliveryHealth, error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	var h DeliveryHealth
	err := s.pool.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM ledger.sessions WHERE initialized AND NOT stopped),
 (SELECT count(*) FROM ledger.intake WHERE processed_at IS NULL),
 (SELECT count(*) FROM ledger.quarantine),
 (SELECT count(*) FROM ledger.work WHERE kind='outbox' AND state IN ('pending','leased','started')),
 (SELECT extract(epoch FROM clock_timestamp()-min(created_at))::double precision FROM ledger.work WHERE kind='outbox' AND state IN ('pending','leased','started')),
 (SELECT extract(epoch FROM clock_timestamp()-max(created_at))::double precision FROM ledger.work WHERE kind='outbox' AND id LIKE 'usage:%')`).Scan(&h.Sessions, &h.Intake, &h.Quarantined, &h.Outbox, &h.OutboxOldestAge, &h.UsageAge)
	return h, safeError(err)
}
