package postgres

import (
	"context"
	"errors"
	"regexp"

	"github.com/jackc/pgx/v5"
)

var transitionDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

func createTransitions(ctx context.Context, tx pgx.Tx, r Roles) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS bootstrap_private.transitions(id text PRIMARY KEY CHECK(id ~ '^[0-9a-f]{64}$'),enabled boolean NOT NULL DEFAULT false,blocked boolean NOT NULL DEFAULT false,created_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
		`CREATE UNIQUE INDEX IF NOT EXISTS one_enabled_transition ON bootstrap_private.transitions(enabled) WHERE enabled`,
		`CREATE TABLE IF NOT EXISTS bootstrap_private.writer_fences(transition text NOT NULL REFERENCES bootstrap_private.transitions(id),node text NOT NULL CHECK(node IN ('radius-primary','radius-secondary')),config_sha256 text NOT NULL CHECK(config_sha256 ~ '^[0-9a-f]{64}$'),receipt_sha256 text NOT NULL CHECK(receipt_sha256 ~ '^[0-9a-f]{64}$'),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(transition,node))`,
		`CREATE TABLE IF NOT EXISTS bootstrap_private.writer_bindings(transition text NOT NULL,node text NOT NULL,config_sha256 text NOT NULL CHECK(config_sha256 ~ '^[0-9a-f]{64}$'),prior_config_sha256 text NOT NULL,receipt_sha256 text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(transition,node,config_sha256),FOREIGN KEY(transition,node) REFERENCES bootstrap_private.writer_fences(transition,node))`,
		`REVOKE ALL ON bootstrap_private.writer_bindings FROM PUBLIC,` + pgx.Identifier{r.Runtime}.Sanitize() + `,` + pgx.Identifier{r.Native}.Sanitize(),
		`CREATE TABLE IF NOT EXISTS bootstrap_private.worker_fences(transition text NOT NULL REFERENCES bootstrap_private.transitions(id),node text NOT NULL CHECK(node IN ('radius-primary','radius-secondary')),receipt_sha256 text NOT NULL CHECK(receipt_sha256 ~ '^[0-9a-f]{64}$'),PRIMARY KEY(transition,node))`,
		`CREATE TABLE IF NOT EXISTS bootstrap_private.worker_states(transition text NOT NULL,node text NOT NULL,receipt_sha256 text NOT NULL,document bytea NOT NULL,PRIMARY KEY(transition,node),FOREIGN KEY(transition,node) REFERENCES bootstrap_private.worker_fences(transition,node))`,
		`REVOKE ALL ON bootstrap_private.worker_states FROM PUBLIC,` + pgx.Identifier{r.Runtime}.Sanitize() + `,` + pgx.Identifier{r.Native}.Sanitize(),
		`CREATE TABLE IF NOT EXISTS bootstrap_private.legacy_usage(transition text PRIMARY KEY REFERENCES bootstrap_private.transitions(id),document bytea NOT NULL,hosts text[] NOT NULL)`,
		`REVOKE ALL ON bootstrap_private.transitions,bootstrap_private.writer_fences,bootstrap_private.worker_fences,bootstrap_private.legacy_usage FROM PUBLIC,` + pgx.Identifier{r.Runtime}.Sanitize() + `,` + pgx.Identifier{r.Native}.Sanitize(),
		`CREATE OR REPLACE FUNCTION ledger.workers_allowed(wanted text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$ SELECT EXISTS(SELECT 1 FROM bootstrap_private.transitions t WHERE t.id=wanted AND t.enabled AND NOT t.blocked AND (SELECT count(*) FROM bootstrap_private.writer_fences f WHERE f.transition=t.id)=2) $$`,
		`CREATE OR REPLACE FUNCTION ledger.lock_worker_transition(wanted text) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$ DECLARE allowed boolean; BEGIN SELECT t.enabled AND NOT t.blocked AND (SELECT count(*) FROM bootstrap_private.writer_fences f WHERE f.transition=t.id)=2 INTO allowed FROM bootstrap_private.transitions t WHERE t.id=wanted FOR SHARE OF t; RETURN coalesce(allowed,false); END $$`,
		`REVOKE ALL ON FUNCTION ledger.lock_worker_transition(text) FROM PUBLIC,` + pgx.Identifier{r.Native}.Sanitize(),
		`GRANT EXECUTE ON FUNCTION ledger.lock_worker_transition(text) TO ` + pgx.Identifier{r.Runtime}.Sanitize(),
		`REVOKE ALL ON FUNCTION ledger.workers_allowed(text) FROM PUBLIC,` + pgx.Identifier{r.Native}.Sanitize(),
		`GRANT EXECUTE ON FUNCTION ledger.workers_allowed(text) TO ` + pgx.Identifier{r.Runtime}.Sanitize(),
	}
	for _, q := range statements {
		if _, err := tx.Exec(ctx, q); err != nil {
			return err
		}
	}
	return createLegacyBundle(ctx, tx, r)
}

// RecordWriterFence accepts only a live root maintenance transaction. Receipt
// hashes refer to root-private originals/quiescence evidence; they are immutable
// and never expire into an automatic retry. Local fencing must precede this call.
func (s *Store) RecordWriterFence(ctx context.Context, id, node, configSHA, receiptSHA string) error {
	scope, ok := ctx.Value(maintenanceScopeKey{}).(*maintenanceScope)
	if !ok || scope.store != s || !scope.active.Load() || !transitionDigest.MatchString(id) || !transitionDigest.MatchString(configSHA) || !transitionDigest.MatchString(receiptSHA) || (node != "radius-primary" && node != "radius-secondary") {
		return errors.New("live protected writer fence evidence required")
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	tx, err := s.begin(ctx)
	if err != nil {
		return safeError(err)
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, `INSERT INTO bootstrap_private.transitions(id) VALUES($1) ON CONFLICT DO NOTHING`, id); err != nil {
		return safeError(err)
	}
	var blocked bool
	if err = tx.QueryRow(ctx, `SELECT blocked FROM bootstrap_private.transitions WHERE id=$1 FOR UPDATE`, id).Scan(&blocked); err != nil {
		return safeError(err)
	}
	if blocked {
		return errors.New("transition revoked")
	}
	var bound bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bootstrap_private.writer_fences f WHERE f.transition=$1 AND f.node=$2 AND f.receipt_sha256=$4 AND (f.config_sha256=$3 OR EXISTS(SELECT 1 FROM bootstrap_private.writer_bindings b WHERE b.transition=$1 AND b.node=$2 AND b.config_sha256=$3 AND b.receipt_sha256=$4)))`, id, node, configSHA, receiptSHA).Scan(&bound); err != nil {
		return safeError(err)
	}
	if bound {
		if err = commit(ctx, tx); err != nil {
			return ErrUncertain
		}
		return nil
	}
	tag, err := tx.Exec(ctx, `INSERT INTO bootstrap_private.writer_fences(transition,node,config_sha256,receipt_sha256) VALUES($1,$2,$3,$4) ON CONFLICT(transition,node) DO UPDATE SET config_sha256=EXCLUDED.config_sha256 WHERE writer_fences.config_sha256=EXCLUDED.config_sha256 AND writer_fences.receipt_sha256=EXCLUDED.receipt_sha256`, id, node, configSHA, receiptSHA)
	if err != nil {
		return safeError(err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("writer fence evidence mismatch")
	}
	if err = commit(ctx, tx); err != nil {
		return ErrUncertain
	}
	return nil
}
func (s *Store) RequireWriterFences(ctx context.Context, id string) error {
	if !transitionDigest.MatchString(id) {
		return errors.New("protected shared transition identity required")
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	var ready bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bootstrap_private.transitions t WHERE t.id=$1 AND NOT t.blocked AND (SELECT count(*) FROM bootstrap_private.writer_fences f WHERE f.transition=t.id)=2)`, id).Scan(&ready)
	if err != nil {
		return safeError(err)
	}
	if !ready {
		return errors.New("both protected legacy writer fences required")
	}
	return nil
}
func (s *Store) WorkersAllowed(ctx context.Context, id string) error {
	if !transitionDigest.MatchString(id) {
		return errors.New("background processing awaits protected transition")
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	var allowed bool
	if err := s.pool.QueryRow(ctx, `SELECT ledger.workers_allowed($1)`, id).Scan(&allowed); err != nil {
		return safeError(err)
	}
	if !allowed {
		return errors.New("background processing fenced pending migration")
	}
	return nil
}
func (s *Store) EnableImportedTransition(ctx context.Context, id string) error {
	if err := s.RequireWriterFences(ctx, id); err != nil {
		return err
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	tag, err := s.pool.Exec(ctx, `UPDATE bootstrap_private.transitions SET enabled=true WHERE id=$1 AND NOT blocked AND EXISTS(SELECT 1 FROM ledger.import_markers WHERE id='state:'||$1) AND (SELECT count(*) FROM bootstrap_private.writer_fences f WHERE f.transition=$1)=2`, id)
	if err != nil {
		return safeError(err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("complete shared state import required")
	}
	return nil
}

// BlockTransition revokes new work before either node is asked to prove its Go
// workers stopped. It does not claim external calls already started are quiescent.
func (s *Store) BlockTransition(ctx context.Context, id string) error {
	if !transitionDigest.MatchString(id) {
		return errors.New("invalid transition")
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	tag, err := s.pool.Exec(ctx, `UPDATE bootstrap_private.transitions SET enabled=false,blocked=true WHERE id=$1`, id)
	if err != nil {
		return safeError(err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("transition unavailable")
	}
	return nil
}

// Node configurations differ. Both nodes must share the transition, while this
// exact node's full protected config must match its root-verified preparation.
func (s *Store) RequireNodeWriterFences(ctx context.Context, id, node, configSHA string) error {
	if !transitionDigest.MatchString(id) || !transitionDigest.MatchString(configSHA) || (node != "radius-primary" && node != "radius-secondary") {
		return errors.New("invalid protected node binding")
	}
	if err := s.RequireWriterFences(ctx, id); err != nil {
		return err
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	var matches bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bootstrap_private.writer_fences WHERE transition=$1 AND node=$2 AND (config_sha256=$3 OR EXISTS(SELECT 1 FROM bootstrap_private.writer_bindings b WHERE b.transition=$1 AND b.node=$2 AND b.config_sha256=$3 AND b.receipt_sha256=writer_fences.receipt_sha256)))`, id, node, configSHA).Scan(&matches); err != nil {
		return safeError(err)
	}
	if !matches {
		return errors.New("local protected configuration differs from preparation")
	}
	return nil
}

// RebindWriterFence appends protected upgrade evidence; original fence rows never
// change. The caller has just reverified the completed old installation and local
// physical quiescence under this same live maintenance scope.
func (s *Store) RebindWriterFence(ctx context.Context, id, node, prior, next, receipt string) error {
	scope, ok := ctx.Value(maintenanceScopeKey{}).(*maintenanceScope)
	if !ok || scope.store != s || !scope.active.Load() || !transitionDigest.MatchString(id) || !transitionDigest.MatchString(prior) || !transitionDigest.MatchString(next) || !transitionDigest.MatchString(receipt) || (node != "radius-primary" && node != "radius-secondary") {
		return errors.New("protected upgrade evidence required")
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	tx, e := s.begin(ctx)
	if e != nil {
		return safeError(e)
	}
	defer rollback(tx)
	var blocked bool
	if e = tx.QueryRow(ctx, `SELECT blocked FROM bootstrap_private.transitions WHERE id=$1 FOR UPDATE`, id).Scan(&blocked); e != nil {
		return safeError(e)
	}
	if blocked {
		return errors.New("transition revoked")
	}
	tag, e := tx.Exec(ctx, `INSERT INTO bootstrap_private.writer_bindings(transition,node,config_sha256,prior_config_sha256,receipt_sha256) SELECT $1,$2,$4,$3,$5 WHERE EXISTS(SELECT 1 FROM bootstrap_private.writer_fences f WHERE f.transition=$1 AND f.node=$2 AND f.receipt_sha256=$5 AND (f.config_sha256=$3 OR EXISTS(SELECT 1 FROM bootstrap_private.writer_bindings b WHERE b.transition=$1 AND b.node=$2 AND b.config_sha256=$3 AND b.receipt_sha256=$5))) ON CONFLICT(transition,node,config_sha256) DO UPDATE SET config_sha256=EXCLUDED.config_sha256 WHERE writer_bindings.prior_config_sha256=EXCLUDED.prior_config_sha256 AND writer_bindings.receipt_sha256=EXCLUDED.receipt_sha256`, id, node, prior, next, receipt)
	if e != nil {
		return safeError(e)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("upgrade does not match original fence")
	}
	if e = commit(ctx, tx); e != nil {
		return ErrUncertain
	}
	return nil
}
