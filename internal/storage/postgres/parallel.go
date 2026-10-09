package postgres

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/migration"
	"github.com/jackc/pgx/v5"
)

func createParallel(ctx context.Context, tx pgx.Tx, r Roles) error {
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS bootstrap_private.parallel_nodes(transition text NOT NULL,role text NOT NULL CHECK(role IN ('radius-primary','radius-secondary')),instance text NOT NULL,manifest text NOT NULL,config text NOT NULL,release_sha256 text NOT NULL,source_digest text NOT NULL,authorization_document bytea NOT NULL,prepared_receipt text NOT NULL DEFAULT '',trust_sha256 text NOT NULL DEFAULT '',ready boolean NOT NULL DEFAULT false,PRIMARY KEY(transition,role))`,
		`REVOKE ALL ON bootstrap_private.parallel_nodes FROM PUBLIC,` + pgx.Identifier{r.Runtime}.Sanitize() + `,` + pgx.Identifier{r.Native}.Sanitize(),
	} {
		if _, err := tx.Exec(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

// ImportParallelAuthorization verifies the source signature again at the storage
// boundary. Only original command quarantine is imported; no old accounting
// state or outbox can be supplied by this closed schema.
func (s *Store) ImportParallelAuthorization(ctx context.Context, c config.Config, release string, raw []byte) error {
	scope, ok := ctx.Value(maintenanceScopeKey{}).(*maintenanceScope)
	if !ok || scope.store != s || !scope.active.Load() {
		return errors.New("protected authorization import required")
	}
	if err := c.ValidateHandoffPins(); err != nil {
		return err
	}
	expected, err := adoption.ExpectedBinding(c, release)
	if err != nil {
		return err
	}
	pin := c.Deployment.SourcePrimaryKey
	if c.InstanceID == "radius-secondary" {
		pin = c.Deployment.SourceSecondaryKey
	}
	key, err := hex.DecodeString(pin)
	if err != nil {
		return err
	}
	doc, err := adoption.Verify(raw, key, expected, time.Now())
	if err != nil {
		return err
	}
	certificates, err := migration.DecodeCertificates(doc.Certificates)
	if err != nil {
		return err
	}
	if certificates.Source != strings.TrimRight(c.Inventory.Fleet.BaseURL, "/") {
		return errors.New("original pending command source differs from destination Fleet authority")
	}
	// Secret native material remains only in the root-owned local transfer.
	doc.Native = nil
	public, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return safeError(err)
	}
	defer rollback(tx)
	var deployment, id, manifest string
	var epoch time.Time
	if err = tx.QueryRow(ctx, `SELECT deployment,transition,manifest_sha256,epoch FROM ledger.collection_epoch WHERE singleton FOR SHARE`).Scan(&deployment, &id, &manifest, &epoch); err != nil {
		return safeError(err)
	}
	if deployment != c.Deployment.ID || id != c.StateTransition || manifest != expected.ManifestSHA256 || !epoch.Equal(expected.CollectionEpoch) {
		return errors.New("authorization differs from immutable collection epoch")
	}
	if _, err = tx.Exec(ctx, `INSERT INTO bootstrap_private.transitions(id) VALUES($1) ON CONFLICT DO NOTHING`, id); err != nil {
		return safeError(err)
	}
	var blocked, enabled bool
	if err = tx.QueryRow(ctx, `SELECT blocked,enabled FROM bootstrap_private.transitions WHERE id=$1 FOR UPDATE`, id).Scan(&blocked, &enabled); err != nil {
		return safeError(err)
	}
	if blocked || enabled {
		return errors.New("authorization handoff requires passive green authority")
	}
	if err = importLegacyCommandGuards(ctx, tx, doc.Certificates); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO bootstrap_private.parallel_nodes(transition,role,instance,manifest,config,release_sha256,source_digest,authorization_document) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(transition,role) DO UPDATE SET source_digest=EXCLUDED.source_digest,authorization_document=EXCLUDED.authorization_document WHERE parallel_nodes.instance=EXCLUDED.instance AND parallel_nodes.manifest=EXCLUDED.manifest AND parallel_nodes.config=EXCLUDED.config AND parallel_nodes.release_sha256=EXCLUDED.release_sha256 AND (NOT parallel_nodes.ready OR parallel_nodes.source_digest=EXCLUDED.source_digest)`, id, c.InstanceID, c.Deployment.Instance, expected.ManifestSHA256, expected.ConfigSHA256, release, adoption.Digest(raw), public)
	if err != nil {
		return safeError(err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("prepared deployment binding changed")
	}
	return safeError(commit(ctx, tx))
}
func (s *Store) RecordParallelPrepared(ctx context.Context, c config.Config, receipt, trust string) error {
	scope, ok := ctx.Value(maintenanceScopeKey{}).(*maintenanceScope)
	if !ok || scope.store != s || !scope.active.Load() || len(receipt) != 32 || !transitionDigest.MatchString(trust) {
		return errors.New("protected physical preparation required")
	}
	raw, _ := json.Marshal(c)
	tag, err := s.pool.Exec(ctx, `UPDATE bootstrap_private.parallel_nodes SET prepared_receipt=$1,trust_sha256=$5 WHERE transition=$2 AND role=$3 AND config=$4 AND (prepared_receipt='' OR prepared_receipt=$1) AND (trust_sha256='' OR trust_sha256=$5)`, receipt, c.StateTransition, c.InstanceID, adoption.Digest(raw), trust)
	if err != nil {
		return safeError(err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("parallel preparation receipt differs")
	}
	return nil
}

// RequireParallelPrepared checks both immutable physical/config publications and
// fresh signed old-side quiescence, never an empty database or expired lease.
func (s *Store) RequireParallelPrepared(ctx context.Context, c config.Config) error {
	manifest, err := c.ParallelManifest()
	if err != nil {
		return err
	}
	rows, err := s.pool.Query(ctx, `SELECT role,instance,manifest,authorization_document,prepared_receipt,trust_sha256,release_sha256,config FROM bootstrap_private.parallel_nodes WHERE transition=$1 ORDER BY role`, c.StateTransition)
	if err != nil {
		return safeError(err)
	}
	defer rows.Close()
	count := 0
	var sharedClass, sharedTrust, sharedRelease string
	for rows.Next() {
		var role, instance, actualManifest, receipt, trust, release, configuration string
		var raw []byte
		if err = rows.Scan(&role, &instance, &actualManifest, &raw, &receipt, &trust, &release, &configuration); err != nil {
			return safeError(err)
		}
		sourceInstance := c.Deployment.SourcePrimary
		if role == "radius-secondary" {
			sourceInstance = c.Deployment.SourceSecondary
		}
		var doc adoption.Authorization
		if json.Unmarshal(raw, &doc) != nil || len(receipt) != 32 || !transitionDigest.MatchString(trust) || actualManifest != manifest || doc.TrustSHA256 != trust || doc.Binding.ReleaseSHA256 != release || doc.Binding.ManifestSHA256 != manifest || doc.Binding.ConfigSHA256 != configuration || doc.Binding.Role != role || doc.Binding.Instance != instance || doc.Binding.Deployment != c.Deployment.ID || doc.Binding.SourceDeployment != c.Deployment.SourceID || doc.Binding.SourceInstance != sourceInstance || doc.Binding.Transition != c.StateTransition || !doc.Binding.CollectionEpoch.Equal(c.Deployment.CollectionEpoch) || instance != c.Deployment.ID+strings.TrimPrefix(role, "radius") || doc.CapturedAt.After(time.Now()) || time.Since(doc.CapturedAt) > adoption.MaxCaptureAge {
			return errors.New("both physical green preparations and fresh old-side fences required")
		}
		if count > 0 && (doc.ClassSHA256 != sharedClass || trust != sharedTrust || release != sharedRelease) {
			return errors.New("green peer Class or CA trust differs")
		}
		sharedClass, sharedTrust, sharedRelease = doc.ClassSHA256, trust, release
		count++
	}
	if err = rows.Err(); err != nil {
		return safeError(err)
	}
	if count != 2 {
		return errors.New("both green nodes must be passively prepared")
	}
	return nil
}

// ReadyParallelNode records authenticated native local/peer readiness only from
// protected activation. The single application authority is enabled atomically
// only after both physical nodes have published readiness for this epoch.
func (s *Store) ReadyParallelNode(ctx context.Context, c config.Config, peerReady bool) (bool, error) {
	scope, ok := ctx.Value(maintenanceScopeKey{}).(*maintenanceScope)
	if !ok || scope.store != s || !scope.active.Load() {
		return false, errors.New("protected activation required")
	}
	if err := s.RequireParallelPrepared(ctx, c); err != nil {
		return false, err
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return false, safeError(err)
	}
	defer rollback(tx)
	var blocked bool
	if err = tx.QueryRow(ctx, `SELECT blocked FROM bootstrap_private.transitions WHERE id=$1 FOR UPDATE`, c.StateTransition).Scan(&blocked); err != nil {
		return false, safeError(err)
	}
	if blocked {
		return false, errors.New("parallel epoch revoked")
	}
	raw, _ := json.Marshal(c)
	tag, err := tx.Exec(ctx, `UPDATE bootstrap_private.parallel_nodes SET ready=true WHERE transition=$1 AND role=$2 AND config=$3`, c.StateTransition, c.InstanceID, adoption.Digest(raw))
	if err != nil {
		return false, safeError(err)
	}
	if tag.RowsAffected() != 1 {
		return false, errors.New("local physical configuration differs")
	}
	var n int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM bootstrap_private.parallel_nodes WHERE transition=$1 AND ready`, c.StateTransition).Scan(&n); err != nil {
		return false, safeError(err)
	}
	if n == 2 && peerReady {
		// These are authenticated SOURCE scheduler receipts, never green-local
		// absence. Keep original role/config/fence hashes for existing worker fencing.
		rows, e := tx.Query(ctx, `SELECT role,config,authorization_document FROM bootstrap_private.parallel_nodes WHERE transition=$1`, c.StateTransition)
		if e != nil {
			return false, safeError(e)
		}
		type proof struct{ role, config, fence string }
		var proofs []proof
		for rows.Next() {
			var p proof
			var data []byte
			if e = rows.Scan(&p.role, &p.config, &data); e != nil {
				rows.Close()
				return false, safeError(e)
			}
			var doc adoption.Authorization
			if json.Unmarshal(data, &doc) != nil {
				rows.Close()
				return false, errors.New("invalid retained source proof")
			}
			p.fence = doc.FenceSHA256
			proofs = append(proofs, p)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return false, safeError(e)
		}
		for _, p := range proofs {
			if _, err = tx.Exec(ctx, `INSERT INTO bootstrap_private.writer_fences(transition,node,config_sha256,receipt_sha256) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, c.StateTransition, p.role, p.config, p.fence); err != nil {
				return false, safeError(err)
			}
		}
		if _, err = tx.Exec(ctx, `UPDATE bootstrap_private.transitions SET enabled=true WHERE id=$1 AND NOT blocked`, c.StateTransition); err != nil {
			return false, safeError(err)
		}
	}
	if err = commit(ctx, tx); err != nil {
		return false, ErrUncertain
	}
	return n == 2 && peerReady, nil
}

// RequireParallelRollbackReady refuses unknown delivery even after leases expire.
// Both physical worker-state receipts and the irrevocably blocked epoch precede
// this check. Accounting data remains entirely in its original green database.
func (s *Store) RequireParallelRollbackReady(ctx context.Context, c config.Config) error {
	if !c.Parallel() {
		return errors.New("parallel rollback authority required")
	}
	if err := s.RequireWorkerExportReady(ctx, c.StateTransition); err != nil {
		return err
	}
	var pending bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ledger.work WHERE payload ? 'collection_key' AND (state NOT IN ('pending','leased') OR EXISTS(SELECT 1 FROM ledger.attempts a WHERE a.work_id=ledger.work.id)) AND (state!='succeeded' OR coalesce(receipt->>'pending','true')!='false')) OR EXISTS(SELECT 1 FROM ledger.legacy_collection_guards WHERE state!='resolved')`).Scan(&pending)
	if err != nil {
		return safeError(err)
	}
	if pending {
		return errors.New("original or green certificate commands remain pending or uncertain; protected terminal reconciliation required")
	}
	return nil
}
