package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/inventory"
	"github.com/CampusTech/cloud-8021x/internal/jobs"
)

var _ inventory.CollectionRepository = (*Store)(nil)

// ReserveCollection fences the host/enrollment scope across every daemon. The
// database clock enforces cadence even if callers disagree about the current hour.
func (s *Store) ReserveCollection(ctx context.Context, id, kind, key string, payload json.RawMessage, cadence time.Duration, maxPending int) (bool, error) {
	var binding struct {
		Key string `json:"collection_key"`
	}
	if id == "" || len(id) > 512 || kind == "" || len(kind) > 64 || key == "" || len(key) > 128 || cadence < time.Hour || cadence > 30*24*time.Hour || maxPending < 1 || maxPending > 2 || len(payload) > 1<<20 || json.Unmarshal(payload, &binding) != nil || binding.Key != key {
		return false, errors.New("invalid collection reservation")
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	tx, err := s.begin(ctx)
	if err != nil {
		return false, safeError(err)
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,80214))", key); err != nil {
		return false, safeError(err)
	}
	var pending int
	var recent bool
	err = tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM ledger.work WHERE payload ? 'collection_key' AND payload->>'collection_key'=$1 AND (state!='succeeded' OR receipt->>'pending'='true')),coalesce((SELECT created_at>clock_timestamp()-$2::bigint*interval '1 millisecond' FROM ledger.work WHERE payload ? 'collection_key' AND payload->>'collection_key'=$1 ORDER BY created_at DESC,id LIMIT 1),false)`, key, cadence.Milliseconds()).Scan(&pending, &recent)
	if err != nil {
		return false, safeError(err)
	}
	if pending >= maxPending || recent {
		return false, nil
	}
	tag, err := tx.Exec(ctx, "INSERT INTO ledger.work(id,kind,payload) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", id, kind, []byte(payload))
	if err != nil {
		return false, safeError(err)
	}
	if tag.RowsAffected() != 1 {
		return false, nil
	}
	if err = commit(ctx, tx); err != nil {
		return false, ErrUncertain
	}
	return true, nil
}
func (s *Store) ListCollection(ctx context.Context, key string) ([]inventory.CollectionWork, error) {
	if key == "" || len(key) > 128 {
		return nil, errors.New("invalid collection key")
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	rows, err := s.pool.Query(ctx, "SELECT id,state,generation,payload,receipt,created_at FROM ledger.work WHERE id IN (SELECT id FROM ledger.work WHERE payload ? 'collection_key' AND payload->>'collection_key'=$1 AND (state!='succeeded' OR receipt->>'pending'='true') UNION ALL (SELECT id FROM ledger.work WHERE payload ? 'collection_key' AND payload->>'collection_key'=$1 AND state='succeeded' AND coalesce(receipt->>'pending','false')!='true' ORDER BY created_at DESC,id LIMIT 2)) ORDER BY created_at DESC,id LIMIT 5", key)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	result := []inventory.CollectionWork{}
	for rows.Next() {
		var item inventory.CollectionWork
		if err = rows.Scan(&item.ID, &item.State, &item.Generation, &item.Payload, &item.Receipt, &item.CreatedAt); err != nil {
			return nil, safeError(err)
		}
		result = append(result, item)
	}
	if err = rows.Err(); err != nil {
		return nil, safeError(err)
	}
	if len(result) > 4 {
		return nil, errors.New("collection history exceeds read bound")
	}
	return result, nil
}

// RecordCollectionResult persists exact adapter-authenticated terminal evidence.
// Pending submitted receipts retain their budget until this transaction commits.
// Original attempt/quarantine history remains untouched.
func (s *Store) RecordCollectionResult(ctx context.Context, id string, generation int64, receipt, evidence json.RawMessage) error {
	if id == "" || generation < 1 || len(receipt) > 1<<20 || len(evidence) > 1<<20 || !json.Valid(receipt) || !json.Valid(evidence) || string(evidence) == "null" {
		return errors.New("invalid collection evidence")
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	tx, err := s.begin(ctx)
	if err != nil {
		return safeError(err)
	}
	defer rollback(tx)
	tag, err := tx.Exec(ctx, `UPDATE ledger.work SET state='succeeded',receipt=$3,updated_at=clock_timestamp() WHERE id=$1 AND generation=$2 AND state IN ('succeeded','quarantine') AND payload ? 'collection_key' AND (state='quarantine' OR receipt->>'pending'='true')`, id, generation, []byte(receipt))
	if err != nil {
		return safeError(err)
	}
	if tag.RowsAffected() != 1 {
		var storedGeneration int64
		var state string
		var equal bool
		err = tx.QueryRow(ctx, "SELECT generation,state,receipt=$2::jsonb FROM ledger.work WHERE id=$1", id, []byte(receipt)).Scan(&storedGeneration, &state, &equal)
		if err != nil {
			return safeError(err)
		}
		if storedGeneration != generation || state != "succeeded" {
			return jobs.ErrFenced
		}
		if !equal {
			return jobs.ErrConflict
		}
		return nil
	}
	if _, err = tx.Exec(ctx, "INSERT INTO ledger.reconciliations(work_id,generation,evidence) VALUES($1,$2,$3)", id, generation, []byte(evidence)); err != nil {
		return safeError(err)
	}
	if err = commit(ctx, tx); err != nil {
		return ErrUncertain
	}
	return nil
}
