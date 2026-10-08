package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/CampusTech/cloud-8021x/internal/migration"
	"github.com/jackc/pgx/v5"
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
func readExportRows(ctx context.Context, tx pgx.Tx, query string, budget *int) ([]json.RawMessage, error) {
	rows, e := tx.Query(ctx, query)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var raw []byte
		if e = rows.Scan(&raw); e != nil {
			return nil, e
		}
		if len(out) >= 100000 || len(raw) > 1<<20 || !json.Valid(raw) {
			return nil, errors.New("rollback table exceeds bounded schema")
		}
		*budget -= len(raw)
		if *budget < 0 {
			return nil, errors.New("rollback ledger exceeds byte bound")
		}
		out = append(out, json.RawMessage(raw))
	}
	return out, rows.Err()
}

// ExportState requires two protected physical worker receipts and preserves every
// outstanding new payload/attempt separately from the legacy DD checkpoint.
// It never changes a work outcome or turns an uncertain delivery into a resend.
func (s *Store) ExportState(ctx context.Context, id string) ([]byte, error) {
	scope, ok := ctx.Value(maintenanceScopeKey{}).(*maintenanceScope)
	if !ok || scope.store != s || !scope.active.Load() || !transitionDigest.MatchString(id) {
		return nil, errors.New("protected cold rollback export required")
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	tx, e := s.begin(ctx)
	if e != nil {
		return nil, safeError(e)
	}
	defer rollback(tx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(8021,2)"); e != nil {
		return nil, safeError(e)
	}
	var fenced bool
	if e = tx.QueryRow(ctx, `SELECT blocked AND NOT enabled AND (SELECT count(*) FROM bootstrap_private.worker_fences WHERE transition=$1)=2 AND (SELECT count(*) FROM bootstrap_private.worker_states WHERE transition=$1)=2 FROM bootstrap_private.transitions WHERE id=$1 FOR UPDATE`, id).Scan(&fenced); e != nil {
		return nil, safeError(e)
	}
	if !fenced {
		return nil, errors.New("both actual worker and current-state receipts required")
	}
	out := migration.RollbackExport{Version: 1, Transition: id, Legacy: map[string]json.RawMessage{}, Current: map[string]json.RawMessage{}, WorkersBlocked: true}
	rows, e := tx.Query(ctx, `SELECT b.node,b.document,w.document FROM bootstrap_private.legacy_bundles b JOIN bootstrap_private.worker_states w ON w.transition=b.transition AND w.node=b.node JOIN bootstrap_private.worker_fences f ON f.transition=w.transition AND f.node=w.node AND f.receipt_sha256=w.receipt_sha256 WHERE b.transition=$1 ORDER BY b.node`, id)
	if e != nil {
		return nil, safeError(e)
	}
	for rows.Next() {
		var node string
		var original, current []byte
		if e = rows.Scan(&node, &original, &current); e != nil {
			rows.Close()
			return nil, e
		}
		b, e := migration.DecodeBundle(original)
		if e != nil {
			rows.Close()
			return nil, e
		}
		n, e := migration.DecodeNodeState(current)
		if e != nil || n.Node != node || n.ClassKeySHA256 != b.ClassKeySHA256 || (!n.FingerprintEnforced && b.FingerprintEnforced) {
			rows.Close()
			return nil, errors.New("current state lost original Class or sticky identity")
		}
		// Authorization snapshot format is directly legacy-compatible. Keep its
		// original generated time; do not rebuild or freshen it during export.
		b.Policy = n.Inventory
		b.FingerprintEnforced = n.FingerprintEnforced
		compatible, e := json.Marshal(b)
		if e != nil {
			rows.Close()
			return nil, e
		}
		out.Legacy[node] = compatible
		out.Current[node] = current
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, safeError(e)
	}
	if len(out.Legacy) != 2 {
		return nil, errors.New("complete original and current node pair unavailable")
	}
	if e = tx.QueryRow(ctx, `SELECT max(version) FROM ledger.schema_version`).Scan(&out.Ledger.SchemaVersion); e != nil {
		return nil, safeError(e)
	}
	budget := 64 << 20
	tables := []struct {
		query  string
		target *[]json.RawMessage
	}{
		{`SELECT row_to_json(t) FROM bootstrap_private.auth_quarantine t ORDER BY source,start_offset LIMIT 100001`, &out.Ledger.AuthQuarantine},
		{`SELECT row_to_json(t) FROM ledger.work t ORDER BY id LIMIT 100001`, &out.Ledger.Work},
		{`SELECT row_to_json(t) FROM ledger.attempts t ORDER BY work_id,generation LIMIT 100001`, &out.Ledger.Attempts},
		{`SELECT row_to_json(t) FROM ledger.reconciliations t ORDER BY work_id,generation LIMIT 100001`, &out.Ledger.Reconciliations},
		{`SELECT row_to_json(t) FROM ledger.legacy_collection_guards t ORDER BY id LIMIT 100001`, &out.Ledger.CollectionGuards},
		{`SELECT row_to_json(t) FROM ledger.sessions t ORDER BY session_key LIMIT 100001`, &out.Ledger.Sessions},
		{`SELECT row_to_json(t) FROM ledger.intake t ORDER BY id LIMIT 100001`, &out.Ledger.Intake},
		{`SELECT row_to_json(t) FROM ledger.observations t ORDER BY event_id LIMIT 100001`, &out.Ledger.Observations},
		{`SELECT row_to_json(t) FROM ledger.intervals t ORDER BY usage_id LIMIT 100001`, &out.Ledger.Intervals},
		{`SELECT row_to_json(t) FROM ledger.quarantine t ORDER BY id LIMIT 100001`, &out.Ledger.Quarantine},
		{`SELECT row_to_json(t) FROM ledger.auth_cursors t ORDER BY source LIMIT 100001`, &out.Ledger.AuthCursors},
	}
	for _, table := range tables {
		*table.target, e = readExportRows(ctx, tx, table.query, &budget)
		if e != nil {
			return nil, safeError(e)
		}
	}
	var usage bool
	if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bootstrap_private.legacy_usage WHERE transition=$1)`, id).Scan(&usage); e != nil {
		return nil, safeError(e)
	}
	// Release the read transaction before the existing bounded usage projection;
	// all producers are physically fenced and the root gate remains exclusive.
	if e = commit(ctx, tx); e != nil {
		return nil, ErrUncertain
	}
	out.UsageAbsent = !usage
	if usage {
		out.Usage, e = s.ExportLegacyUsage(ctx, id)
		if e != nil {
			return nil, e
		}
	}
	data, e := json.Marshal(out)
	if e != nil {
		return nil, e
	}
	if len(data) > 256<<20 {
		return nil, errors.New("rollback export exceeds total bound")
	}
	return data, nil
}

// Read-only operator preflight. The live export repeats this proof under its
// maintenance scope and row lock; an early invocation must not quarantine it.
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
