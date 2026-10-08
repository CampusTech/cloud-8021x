package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/jobs"
	"github.com/jackc/pgx/v5"
)

var _ jobs.Coordinator = (*Store)(nil)

func (s *Store) Reserve(ctx context.Context, id, kind string, payload json.RawMessage) error {
	if id == "" || kind == "" || len(id) > 512 || len(kind) > 64 || len(payload) > 1<<20 || !json.Valid(payload) {
		return errors.New("invalid work reservation")
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	tag, err := s.pool.Exec(ctx, `INSERT INTO ledger.work(id,kind,payload) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET id=EXCLUDED.id WHERE ledger.work.kind=EXCLUDED.kind AND ledger.work.payload=EXCLUDED.payload`, id, kind, []byte(payload))
	if err != nil {
		return safeError(err)
	}
	if tag.RowsAffected() != 1 {
		return jobs.ErrConflict
	}
	return nil
}
func (s *Store) Claim(ctx context.Context, kind, owner string, lease time.Duration) (*jobs.Claim, error) {
	if kind == "" || owner == "" || len(owner) > 128 || lease < time.Second || lease > 10*time.Minute {
		return nil, errors.New("invalid work claim")
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, safeError(err)
	}
	defer rollback(tx)
	// Bounded sweep; the statement locks the same work rows as completion. A crash
	// after Start therefore preserves a reconciliation obligation, not a retry.
	_, err = tx.Exec(ctx, `WITH expired AS (
 SELECT id FROM ledger.work WHERE kind=$1 AND state='started' AND lease_until<=clock_timestamp() ORDER BY lease_until FOR UPDATE SKIP LOCKED LIMIT 64
 ), changed AS (
 UPDATE ledger.work w SET state='quarantine',updated_at=clock_timestamp() FROM expired e WHERE w.id=e.id RETURNING w.id,w.generation
 ), attempts AS (
 UPDATE ledger.attempts a SET finished_at=clock_timestamp(),outcome='uncertain' FROM changed c WHERE a.work_id=c.id AND a.generation=c.generation
 ) INSERT INTO ledger.quarantine(work_id,reason) SELECT id,'expired_started_attempt' FROM changed`, kind)
	if err != nil {
		return nil, safeError(err)
	}
	claim := &jobs.Claim{}
	err = tx.QueryRow(ctx, `WITH candidate AS (
 SELECT id FROM ledger.work WHERE kind=$1 AND (state='pending' OR (state='leased' AND lease_until<=clock_timestamp())) ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 1
 ) UPDATE ledger.work w SET state='leased',owner=$2,generation=generation+1,lease_until=clock_timestamp()+$3::bigint*interval '1 millisecond',updated_at=clock_timestamp() FROM candidate c WHERE w.id=c.id RETURNING w.id,w.kind,w.owner,w.generation,w.lease_until,w.payload`, kind, owner, lease.Milliseconds()).Scan(&claim.ID, &claim.Kind, &claim.Owner, &claim.Generation, &claim.LeaseUntil, &claim.Payload)
	if errors.Is(err, pgx.ErrNoRows) {
		claim = nil
	} else if err != nil {
		return nil, safeError(err)
	}
	if err = commit(ctx, tx); err != nil {
		return nil, ErrUncertain
	}
	return claim, nil
}
func (s *Store) StartAttempt(ctx context.Context, c jobs.Claim) error {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	tx, err := s.begin(ctx)
	if err != nil {
		return safeError(err)
	}
	defer rollback(tx)
	tag, err := tx.Exec(ctx, `WITH started AS (
 UPDATE ledger.work SET state='started',updated_at=clock_timestamp() WHERE id=$1 AND owner=$2 AND generation=$3 AND state='leased' AND lease_until>clock_timestamp() RETURNING id,generation,owner
 ) INSERT INTO ledger.attempts(work_id,generation,owner) SELECT id,generation,owner FROM started`, c.ID, c.Owner, c.Generation)
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

// FinishAttempt never retries an ambiguous or partial external result. Even a
// definite rejection is retained for explicit reconciliation, not a hot loop.
func (s *Store) FinishAttempt(ctx context.Context, c jobs.Claim, outcome jobs.Outcome, receipt json.RawMessage) error {
	if outcome != jobs.Succeeded && outcome != jobs.Uncertain && outcome != jobs.Partial && outcome != jobs.Rejected {
		return errors.New("invalid attempt outcome")
	}
	if len(receipt) > 1<<20 || !json.Valid(receipt) {
		return errors.New("invalid attempt receipt")
	}
	state := "quarantine"
	if outcome == jobs.Succeeded {
		state = "succeeded"
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	tx, err := s.begin(ctx)
	if err != nil {
		return safeError(err)
	}
	defer rollback(tx)
	tag, err := tx.Exec(ctx, `UPDATE ledger.work SET state=$4,receipt=$5,updated_at=clock_timestamp() WHERE id=$1 AND owner=$2 AND generation=$3 AND state='started' AND lease_until>clock_timestamp()`, c.ID, c.Owner, c.Generation, state, []byte(receipt))
	if err != nil {
		return safeError(err)
	}
	if tag.RowsAffected() != 1 {
		return jobs.ErrFenced
	}
	if _, err = tx.Exec(ctx, "UPDATE ledger.attempts SET finished_at=clock_timestamp(),outcome=$3,receipt=$4 WHERE work_id=$1 AND generation=$2", c.ID, c.Generation, string(outcome), []byte(receipt)); err != nil {
		return safeError(err)
	}
	if state == "quarantine" {
		if _, err = tx.Exec(ctx, "INSERT INTO ledger.quarantine(work_id,reason,payload) VALUES($1,$2,$3)", c.ID, string(outcome), []byte(receipt)); err != nil {
			return safeError(err)
		}
	}
	if err = commit(ctx, tx); err != nil {
		return ErrUncertain
	}
	return nil
}

type WorkState struct {
	State            string
	Generation       int64
	Owner            string
	Payload, Receipt json.RawMessage
}

// LookupWork resolves uncertain commits. Callers must NOT submit I/O after an
// uncertain Start, even if this lookup finds started: a different process may
// already have issued it. Reconciliation uses authenticated external evidence.
func (s *Store) LookupWork(ctx context.Context, id string) (WorkState, error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	var w WorkState
	err := s.pool.QueryRow(ctx, "SELECT state,generation,coalesce(owner,''),payload,receipt FROM ledger.work WHERE id=$1", id).Scan(&w.State, &w.Generation, &w.Owner, &w.Payload, &w.Receipt)
	return w, safeError(err)
}
