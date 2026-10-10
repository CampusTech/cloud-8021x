package postgres

import (
	"context"
	"errors"

	"github.com/CampusTech/cloud-8021x/internal/migration"
)

func (s *Store) RecordWorkerState(ctx context.Context, id, receipt string, data []byte) error {
	scope, ok := ctx.Value(maintenanceScopeKey{}).(*maintenanceScope)
	if !ok || scope.store != s || !scope.active.Load() {
		return errors.New("protected worker state scope required")
	}
	state, e := migration.DecodeNodeState(data)
	if e != nil {
		return e
	}
	if e = s.RecordWorkerFence(ctx, id, state.Node, receipt); e != nil {
		return e
	}
	tag, e := s.pool.Exec(ctx, `INSERT INTO bootstrap_private.worker_states(transition,node,receipt_sha256,document) VALUES($1,$2,$3,$4) ON CONFLICT(transition,node) DO UPDATE SET receipt_sha256=EXCLUDED.receipt_sha256 WHERE worker_states.receipt_sha256=EXCLUDED.receipt_sha256 AND worker_states.document=EXCLUDED.document`, id, state.Node, receipt, data)
	if e != nil {
		return safeError(e)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("original worker state differs")
	}
	return nil
}
func (s *Store) RecordWorkerFence(ctx context.Context, id, node, receipt string) error {
	scope, ok := ctx.Value(maintenanceScopeKey{}).(*maintenanceScope)
	if !ok || scope.store != s || !scope.active.Load() || !transitionDigest.MatchString(id) || !transitionDigest.MatchString(receipt) || (node != "radius-primary" && node != "radius-secondary") {
		return errors.New("protected worker quiescence evidence required")
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	tag, err := s.pool.Exec(ctx, `INSERT INTO bootstrap_private.worker_fences(transition,node,receipt_sha256) SELECT $1,$2,$3 WHERE EXISTS(SELECT 1 FROM bootstrap_private.transitions WHERE id=$1 AND blocked AND NOT enabled) ON CONFLICT(transition,node) DO UPDATE SET receipt_sha256=EXCLUDED.receipt_sha256 WHERE worker_fences.receipt_sha256=EXCLUDED.receipt_sha256`, id, node, receipt)
	if err != nil {
		return safeError(err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("revoke transition before fencing workers; receipt must match")
	}
	return nil
}

// Read-only operator and parallel rollback preflight. Both nodes must retain
// matching physical worker fences and original current-state receipts.
func (s *Store) RequireWorkerExportReady(ctx context.Context, id string) error {
	if !transitionDigest.MatchString(id) {
		return errors.New("invalid transition")
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	var ready bool
	e := s.pool.QueryRow(ctx, `SELECT blocked AND NOT enabled AND (SELECT count(*) FROM bootstrap_private.worker_fences f JOIN bootstrap_private.worker_states w ON w.transition=f.transition AND w.node=f.node AND w.receipt_sha256=f.receipt_sha256 WHERE f.transition=$1)=2 FROM bootstrap_private.transitions WHERE id=$1`, id).Scan(&ready)
	if e != nil {
		return safeError(e)
	}
	if !ready {
		return errors.New("both physical worker fences and original current-state receipts required")
	}
	return nil
}
