package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
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

// UnresolvedSourcePayloads supplies retention references without changing claims,
// original candidate timestamps or reconciliation state. Any uncertainty means
// the protected helper retains proof rather than deleting it by age.
func (s *Store) UnresolvedSourcePayloads(ctx context.Context, node string) ([][]byte, error) {
	if node != "radius-primary" && node != "radius-secondary" {
		return nil, errors.New("invalid fixed source node")
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT payload FROM ledger.work WHERE kind=$1 AND state IN ('pending','leased','started','quarantine') ORDER BY id LIMIT 1025`, "sources:"+node)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	var payloads [][]byte
	for rows.Next() {
		var payload []byte
		if err = rows.Scan(&payload); err != nil {
			return nil, safeError(err)
		}
		if len(payload) > 1<<20 || len(payloads) >= 1024 {
			return nil, errors.New("source retention references exceed bound")
		}
		payloads = append(payloads, payload)
	}
	return payloads, safeError(rows.Err())
}

// ReconcileHistoricalSource holds the fixed node claim lock and exact quarantine
// row while the installed root verifier reads actual file/firewall/proof state.
// Only a live protected maintenance scope can invoke it. It never creates work,
// starts an attempt, changes payload/candidate time, or authorizes any resend.
func (s *Store) ReconcileHistoricalSource(ctx context.Context, transition, node, id string, generation int64, verify func(context.Context, json.RawMessage) (json.RawMessage, error)) error {
	scope, ok := ctx.Value(maintenanceScopeKey{}).(*maintenanceScope)
	if !ok || scope.store != s || !scope.active.Load() || verify == nil || generation < 1 || (node != "radius-primary" && node != "radius-secondary") {
		return errors.New("live protected source recovery required")
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return safeError(e)
	}
	defer rollback(tx)
	var allowed bool
	if e = tx.QueryRow(ctx, "SELECT ledger.lock_worker_transition($1)", transition).Scan(&allowed); e != nil {
		return safeError(e)
	}
	if !allowed {
		return errors.New("historical source recovery transition fenced")
	}
	lock := 100
	if node == "radius-secondary" {
		lock = 101
	}
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(8021,$1)", lock); e != nil {
		return safeError(e)
	}
	var payload []byte
	if e = tx.QueryRow(ctx, `SELECT payload FROM ledger.work WHERE id=$1 AND kind=$2 AND generation=$3 AND (state='quarantine' OR (state='started' AND lease_until<=clock_timestamp())) AND NOT EXISTS(SELECT 1 FROM bootstrap_private.source_history h WHERE h.work_id=ledger.work.id AND h.generation=ledger.work.generation) FOR UPDATE`, id, "sources:"+node, generation).Scan(&payload); e != nil {
		return errors.New("exact quarantined source attempt unavailable")
	}
	evidence, e := verify(ctx, payload)
	if e != nil {
		return e
	}
	if len(evidence) == 0 || len(evidence) > 1<<20 || !json.Valid(evidence) || string(evidence) == "null" {
		return errors.New("invalid protected historical proof")
	}
	if _, e = tx.Exec(ctx, `INSERT INTO bootstrap_private.source_history(work_id,generation,transition,node,payload,evidence) VALUES($1,$2,$3,$4,$5,$6)`, id, generation, transition, node, payload, []byte(evidence)); e != nil {
		return safeError(e)
	}
	if _, e = tx.Exec(ctx, `INSERT INTO ledger.reconciliations(work_id,generation,evidence) VALUES($1,$2,$3)`, id, generation, []byte(evidence)); e != nil {
		return safeError(e)
	}
	if _, e = tx.Exec(ctx, `UPDATE ledger.work SET state='succeeded',updated_at=clock_timestamp() WHERE id=$1`, id); e != nil {
		return safeError(e)
	}
	if e = commit(ctx, tx); e != nil {
		return ErrUncertain
	}
	return nil
}

// HistoricalSourceRecorded is proof-only. The root-private row cannot be forged
// by the runtime role. An absent row is useful only with the exact unresolved
// original and independent physical helper/installed-state proof at the caller.
func (s *Store) HistoricalSourceRecorded(ctx context.Context, transition, node, id string, generation int64, payload, evidence json.RawMessage) (string, error) {
	if generation < 1 || len(payload) > 1<<20 || len(evidence) > 1<<20 || !json.Valid(payload) || !json.Valid(evidence) || (node != "radius-primary" && node != "radius-secondary") {
		return "", errors.New("invalid source history identity")
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	var state string
	var expired, history, exact bool
	e := s.pool.QueryRow(ctx, `SELECT w.state,coalesce(w.lease_until<=clock_timestamp(),false),h.work_id IS NOT NULL,coalesce(h.transition=$4 AND h.node=$2 AND h.payload=$5::jsonb AND h.evidence=$6::jsonb,false) FROM ledger.work w LEFT JOIN bootstrap_private.source_history h ON h.work_id=w.id AND h.generation=w.generation WHERE w.id=$1 AND w.kind='sources:'||$2 AND w.generation=$3 AND w.payload=$5::jsonb AND EXISTS(SELECT 1 FROM bootstrap_private.writer_fences f WHERE f.transition=$4 AND f.node=$2)`, id, node, generation, transition, []byte(payload), []byte(evidence)).Scan(&state, &expired, &history, &exact)
	if e != nil {
		return "", safeError(e)
	}
	if state == "succeeded" && history && exact {
		return "committed", nil
	}
	if !history && (state == "quarantine" || state == "started" && expired) {
		return "uncommitted", nil
	}
	return "", errors.New("unknown or mismatched original source history")
}

// SourceMaintenanceAttempt exposes only the current fixed source operation's
// journal identity to its original protected local receipt.
func (s *Store) SourceMaintenanceAttempt(ctx context.Context, operation string) (int64, error) {
	scope, ok := ctx.Value(maintenanceScopeKey{}).(*maintenanceScope)
	if !ok || scope.store != s || !scope.active.Load() || (!strings.HasPrefix(operation, "sources-apply:") && !strings.HasPrefix(operation, "source-history:")) {
		return 0, errors.New("owned source operation required")
	}
	var id int64
	e := s.pool.QueryRow(ctx, `SELECT id FROM bootstrap_private.maintenance WHERE id=$1 AND operation=$2 AND outcome='started' AND expires_at>clock_timestamp()`, scope.id, operation).Scan(&id)
	return id, safeError(e)
}
