package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/jobs"
)

// Renew cannot revive an expired claim or change its generation. External API
// timeouts must remain bounded; renewal is not permission to repeat an attempt.
func (s *Store) Renew(ctx context.Context, c jobs.Claim, lease time.Duration) error {
	if lease < time.Second || lease > 10*time.Minute {
		return errors.New("invalid work lease")
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	tx, err := s.begin(ctx)
	if err != nil {
		return safeError(err)
	}
	defer rollback(tx)
	tag, err := tx.Exec(ctx, `UPDATE ledger.work SET lease_until=clock_timestamp()+$4::bigint*interval '1 millisecond',updated_at=clock_timestamp() WHERE id=$1 AND owner=$2 AND generation=$3 AND state IN ('leased','started') AND lease_until>clock_timestamp()`, c.ID, c.Owner, c.Generation, lease.Milliseconds())
	if err != nil {
		return safeError(err)
	}
	if tag.RowsAffected() != 1 {
		return jobs.ErrFenced
	}
	if err = commit(ctx, tx); err != nil {
		return ErrUncertain
	}
	return nil
}

// ReconcileSuccess records authenticated external evidence that a quarantined
// attempt already succeeded. It never authorizes a resend. The adapter is
// responsible for verifying the evidence (command/activity ID or handoff receipt).
func (s *Store) ReconcileSuccess(ctx context.Context, id string, generation int64, evidence json.RawMessage) error {
	if id == "" || generation < 1 || len(evidence) > 1<<20 || !json.Valid(evidence) || string(evidence) == "null" {
		return errors.New("invalid reconciliation evidence")
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	tx, err := s.begin(ctx)
	if err != nil {
		return safeError(err)
	}
	defer rollback(tx)
	tag, err := tx.Exec(ctx, "UPDATE ledger.work SET state='succeeded',updated_at=clock_timestamp() WHERE id=$1 AND generation=$2 AND state='quarantine'", id, generation)
	if err != nil {
		return safeError(err)
	}
	if tag.RowsAffected() != 1 {
		return jobs.ErrFenced
	}
	if _, err = tx.Exec(ctx, "INSERT INTO ledger.reconciliations(work_id,generation,evidence) VALUES($1,$2,$3)", id, generation, []byte(evidence)); err != nil {
		return safeError(err)
	}
	if err = commit(ctx, tx); err != nil {
		return ErrUncertain
	}
	return nil
}
