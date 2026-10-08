package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/jobs"
	"github.com/jackc/pgx/v5"
)

// ClaimSource is the exclusive claiming API for source work. It serializes the
// immutable node resource across all candidate revisions and blocks unresolved
// outcomes until explicit authenticated reconciliation releases them.
func (s *Store) ClaimSource(ctx context.Context, node, owner string, lease time.Duration) (*jobs.Claim, error) {
	lock := 100
	if node == "radius-secondary" {
		lock = 101
	} else if node != "radius-primary" {
		return nil, errors.New("invalid fixed source node")
	}
	if owner == "" || len(owner) > 128 || lease < time.Second || lease > 10*time.Minute {
		return nil, errors.New("invalid source claim")
	}
	kind := "sources:" + node
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	tx, e := s.begin(ctx)
	if e != nil {
		return nil, safeError(e)
	}
	defer rollback(tx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(8021,$1)", lock); e != nil {
		return nil, safeError(e)
	}
	_, e = tx.Exec(ctx, `WITH changed AS (
 UPDATE ledger.work SET state='quarantine',updated_at=clock_timestamp() WHERE kind=$1 AND state='started' AND lease_until<=clock_timestamp() RETURNING id,generation
 ), attempts AS (
 UPDATE ledger.attempts a SET finished_at=clock_timestamp(),outcome='uncertain' FROM changed c WHERE a.work_id=c.id AND a.generation=c.generation
 ) INSERT INTO ledger.quarantine(work_id,reason) SELECT id,'expired_source_attempt' FROM changed`, kind)
	if e != nil {
		return nil, safeError(e)
	}
	var blocked bool
	if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ledger.work WHERE kind=$1 AND (state IN ('started','quarantine') OR (state='leased' AND lease_until>clock_timestamp())))`, kind).Scan(&blocked); e != nil {
		return nil, safeError(e)
	}
	if blocked {
		if e = commit(ctx, tx); e != nil {
			return nil, ErrUncertain
		}
		return nil, nil
	}
	claim := &jobs.Claim{}
	e = tx.QueryRow(ctx, `WITH candidate AS (
 SELECT id FROM ledger.work WHERE kind=$1 AND (state='pending' OR (state='leased' AND lease_until<=clock_timestamp())) ORDER BY created_at,id FOR UPDATE LIMIT 1
 ) UPDATE ledger.work w SET state='leased',owner=$2,generation=generation+1,lease_until=clock_timestamp()+$3::bigint*interval '1 millisecond',updated_at=clock_timestamp() FROM candidate c WHERE w.id=c.id RETURNING w.id,w.kind,w.owner,w.generation,w.lease_until,w.payload`, kind, owner, lease.Milliseconds()).Scan(&claim.ID, &claim.Kind, &claim.Owner, &claim.Generation, &claim.LeaseUntil, &claim.Payload)
	if errors.Is(e, pgx.ErrNoRows) {
		claim = nil
	} else if e != nil {
		return nil, safeError(e)
	}
	if e = commit(ctx, tx); e != nil {
		return nil, ErrUncertain
	}
	return claim, nil
}
