package postgres

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/migration"
	"github.com/jackc/pgx/v5"
)

func (s *Store) RequireFreshEmpty(ctx context.Context, id string) error {
	scope, ok := ctx.Value(maintenanceScopeKey{}).(*maintenanceScope)
	if !ok || scope.store != s || !scope.active.Load() {
		return errors.New("protected fresh preparation required")
	}
	var clear bool
	e := s.pool.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM bootstrap_private.transitions WHERE id<>$1 OR enabled OR blocked) AND NOT EXISTS(SELECT 1 FROM bootstrap_private.operator_recovery) AND NOT EXISTS(SELECT 1 FROM ledger.work) AND NOT EXISTS(SELECT 1 FROM ledger.legacy_usage_floor) AND NOT EXISTS(SELECT 1 FROM ledger.sessions) AND NOT EXISTS(SELECT 1 FROM ledger.intake) AND NOT EXISTS(SELECT 1 FROM ledger.observations) AND NOT EXISTS(SELECT 1 FROM ledger.legacy_collection_guards) AND NOT EXISTS(SELECT 1 FROM bootstrap_private.legacy_bundles) AND NOT EXISTS(SELECT 1 FROM ledger.import_markers) AND NOT EXISTS(SELECT 1 FROM ledger.auth_cursors) AND NOT EXISTS(SELECT 1 FROM ledger.intervals) AND NOT EXISTS(SELECT 1 FROM ledger.attempts) AND NOT EXISTS(SELECT 1 FROM ledger.reconciliations) AND NOT EXISTS(SELECT 1 FROM ledger.quarantine) AND NOT EXISTS(SELECT 1 FROM bootstrap_private.legacy_usage) AND NOT EXISTS(SELECT 1 FROM bootstrap_private.worker_states) AND NOT EXISTS(SELECT 1 FROM bootstrap_private.auth_quarantine) AND NOT EXISTS(SELECT 1 FROM bootstrap_private.source_history) AND NOT EXISTS(SELECT 1 FROM bootstrap_private.fresh_seeds WHERE transition<>$1)`, id).Scan(&clear)
	if e != nil {
		return safeError(e)
	}
	if !clear {
		return errors.New("fresh preparation refuses existing shared authority or unknown rejoin")
	}
	return nil
}
func (s *Store) RecordFreshSeed(ctx context.Context, id, hash string, raw []byte) error {
	b, e := migration.DecodeBundle(raw)
	if e != nil || b.FreshAbsenceSHA256 == "" || !transitionDigest.MatchString(hash) {
		return errors.New("typed original fresh seed required")
	}
	if e = s.RequireFreshEmpty(ctx, id); e != nil {
		return e
	}
	rows, e := s.pool.Query(ctx, `SELECT document FROM bootstrap_private.fresh_seeds WHERE transition=$1`, id)
	if e != nil {
		return safeError(e)
	}
	for rows.Next() {
		var existing []byte
		if e = rows.Scan(&existing); e != nil {
			rows.Close()
			return safeError(e)
		}
		prior, e := migration.DecodeBundle(existing)
		if e != nil || prior.ClassKeySHA256 != b.ClassKeySHA256 {
			rows.Close()
			return errors.New("fresh pair Class differs")
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return safeError(e)
	}
	tag, e := s.pool.Exec(ctx, `INSERT INTO bootstrap_private.fresh_seeds(transition,node,config_sha256,checksum,document) VALUES($1,$2,$3,$4,$5) ON CONFLICT(transition,node) DO UPDATE SET checksum=EXCLUDED.checksum WHERE fresh_seeds.config_sha256=EXCLUDED.config_sha256 AND fresh_seeds.document=EXCLUDED.document`, id, b.Node, hash, bundleDigest(raw), raw)
	if e != nil {
		return safeError(e)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("original fresh seed changed")
	}
	return nil
}
func (s *Store) FreshInventory(ctx context.Context, id, node, hash, bundle string) ([]byte, error) {
	var raw []byte
	e := s.pool.QueryRow(ctx, `SELECT i.snapshot FROM bootstrap_private.fresh_inventory i JOIN bootstrap_private.fresh_seeds f USING(transition,node) WHERE i.transition=$1 AND i.node=$2 AND i.config_sha256=$3 AND i.bundle_sha256=$4 AND f.config_sha256=i.config_sha256 AND f.checksum=i.bundle_sha256`, id, node, hash, bundle).Scan(&raw)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, os.ErrNotExist
	}
	return raw, safeError(e)
}
func (s *Store) RecordFreshInventory(ctx context.Context, id, node, hash, bundle string, snapshot []byte) error {
	if e := s.RequireFreshEmpty(ctx, id); e != nil {
		return e
	}
	if e := s.RequireNodeWriterFences(ctx, id, node, hash); e != nil {
		return e
	}
	parsed, e := domain.DecodeSnapshot(bytes.NewReader(snapshot))
	if e != nil || parsed.Version != 2 || parsed.UpdatedAt <= 0 || len(parsed.Identities) == 0 || len(parsed.Certificates) != 0 || len(parsed.HardwareSerials) != 0 {
		return errors.New("fresh observer snapshot must have observed identities without certificate authorization")
	}
	var count int
	if e = s.pool.QueryRow(ctx, `SELECT count(*) FROM bootstrap_private.fresh_seeds WHERE transition=$1`, id).Scan(&count); e != nil {
		return safeError(e)
	}
	if count != 2 {
		return errors.New("both protected fresh originals required")
	}
	tag, e := s.pool.Exec(ctx, `INSERT INTO bootstrap_private.fresh_inventory(transition,node,config_sha256,bundle_sha256,snapshot) SELECT $1,$2,$3,$4,$5 WHERE EXISTS(SELECT 1 FROM bootstrap_private.fresh_seeds WHERE transition=$1 AND node=$2 AND config_sha256=$3 AND checksum=$4) ON CONFLICT(transition,node) DO UPDATE SET bundle_sha256=EXCLUDED.bundle_sha256 WHERE fresh_inventory.config_sha256=EXCLUDED.config_sha256 AND fresh_inventory.bundle_sha256=EXCLUDED.bundle_sha256 AND fresh_inventory.snapshot=EXCLUDED.snapshot`, id, node, hash, bundle, snapshot)
	if e != nil {
		return safeError(e)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("fresh initial authority differs from original receipt")
	}
	return nil
}

// FreshInitialAttempt exposes only the current fixed preparation journal.
func (s *Store) FreshInitialAttempt(ctx context.Context, operation string) (int64, error) {
	scope, ok := ctx.Value(maintenanceScopeKey{}).(*maintenanceScope)
	if !ok || scope.store != s || !scope.active.Load() || !strings.HasPrefix(operation, "fresh-initial:") || !transitionDigest.MatchString(strings.TrimPrefix(operation, "fresh-initial:")) {
		return 0, errors.New("owned fresh initial operation required")
	}
	var id int64
	e := s.pool.QueryRow(ctx, `SELECT id FROM bootstrap_private.maintenance WHERE id=$1 AND operation=$2 AND outcome='started' AND expires_at>clock_timestamp()`, scope.id, operation).Scan(&id)
	return id, safeError(e)
}

// FreshInitialRecorded is a proof-only lookup. A mismatched row is unknown,
// never absence; no-commit recovery also excludes all later bootstrap phases.
func (s *Store) FreshInitialRecorded(ctx context.Context, id, node, hash, bundle string, snapshot []byte) (bool, error) {
	var cfg, digest string
	var raw []byte
	e := s.pool.QueryRow(ctx, `SELECT config_sha256,bundle_sha256,snapshot FROM bootstrap_private.fresh_inventory WHERE transition=$1 AND node=$2`, id, node).Scan(&cfg, &digest, &raw)
	if e == nil {
		if cfg != hash || digest != bundle || !bytes.Equal(raw, snapshot) {
			return false, errors.New("initial snapshot differs")
		}
		return true, nil
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return false, safeError(e)
	}
	var clear bool
	e = s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bootstrap_private.fresh_seeds WHERE transition=$1 AND node=$2 AND config_sha256=$3 AND checksum=$4) AND NOT EXISTS(SELECT 1 FROM bootstrap_private.legacy_bundles) AND NOT EXISTS(SELECT 1 FROM bootstrap_private.ca_publication) AND NOT EXISTS(SELECT 1 FROM bootstrap_private.maintenance WHERE operation IN ('bootstrap','certificates renew') OR installation<>'') AND NOT EXISTS(SELECT 1 FROM bootstrap_private.operator_recovery) AND NOT EXISTS(SELECT 1 FROM ledger.work) AND NOT EXISTS(SELECT 1 FROM ledger.import_markers) AND NOT EXISTS(SELECT 1 FROM bootstrap_private.transitions WHERE id<>$1 OR enabled OR blocked)`, id, node, hash, bundle).Scan(&clear)
	if e != nil {
		return false, safeError(e)
	}
	if !clear {
		return false, errors.New("absent fresh row has unknown or later state")
	}
	return false, nil
}

func (s *Store) LegacyCaptureAttempt(ctx context.Context, operation string) (int64, error) {
	scope, ok := ctx.Value(maintenanceScopeKey{}).(*maintenanceScope)
	if !ok || scope.store != s || !scope.active.Load() || !strings.HasPrefix(operation, "legacy-capture:") || !transitionDigest.MatchString(strings.TrimPrefix(operation, "legacy-capture:")) {
		return 0, errors.New("owned legacy capture preparation required")
	}
	var id int64
	e := s.pool.QueryRow(ctx, `SELECT id FROM bootstrap_private.maintenance WHERE id=$1 AND operation=$2 AND outcome='started' AND expires_at>clock_timestamp()`, scope.id, operation).Scan(&id)
	return id, safeError(e)
}

// LegacyCaptureBeforeInstall is proof-only and cannot authorize a fresh SQL read.
func (s *Store) LegacyCaptureBeforeInstall(ctx context.Context, id, node, hash, writer string) error {
	if e := s.RequireNodeWriterFences(ctx, id, node, hash); e != nil {
		return e
	}
	var clear bool
	e := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bootstrap_private.writer_fences WHERE transition=$1 AND node=$2 AND config_sha256=$3 AND receipt_sha256=$4) AND NOT EXISTS(SELECT 1 FROM bootstrap_private.legacy_bundles WHERE transition=$1 AND node=$2) AND NOT EXISTS(SELECT 1 FROM bootstrap_private.maintenance WHERE operation IN ('bootstrap','certificates renew') OR installation<>'') AND NOT EXISTS(SELECT 1 FROM bootstrap_private.ca_publication) AND NOT EXISTS(SELECT 1 FROM bootstrap_private.transitions WHERE id<>$1 OR enabled OR blocked)`, id, node, hash, writer).Scan(&clear)
	if e != nil {
		return safeError(e)
	}
	if !clear {
		return errors.New("legacy capture has later or unknown installation state")
	}
	return nil
}
