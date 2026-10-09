//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
	"github.com/CampusTech/cloud-8021x/internal/telemetry"
	"github.com/jackc/pgx/v5"
)

// Fixed queries, no operator SQL and no writes. The protected migration role is
// needed to read original root-only recovery receipts; runtime/CA ACLs are unchanged.
func observeSQL(ctx context.Context, project bool) (out sqlObservation, err error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cfg, manifest, err := nodeConfig()
	if err != nil {
		return out, err
	}
	if cfg.Deployment.ID != "task11-green" || cfg.Database.Name != "cloud8021x_task11_green" || len(cfg.Network.Providers) != 0 {
		return out, errors.New("fixed synthetic database and no changing network enrichment required")
	}
	installed, err := readPrivate("/etc/cloud-8021x/config.yaml", config.MaxConfigBytes, 0)
	if err != nil || adoption.Digest(installed) != manifest.ConfigSHA256 {
		return out, errors.New("installed and enrolled configuration differ")
	}
	clear(installed)
	out.ConfigSHA256 = manifest.ConfigSHA256
	unlock, err := host.AcquireWriterOperation()
	if err != nil {
		return out, err
	}
	defer unlock()
	dsn, err := readPrivate(cfg.Database.MigrationDSN.File, 64<<10, 0)
	if err != nil {
		return out, err
	}
	defer clear(dsn)
	cc, err := pgx.ParseConfig(strings.TrimSpace(string(dsn)))
	if err != nil {
		return out, errors.New("protected SQL credential invalid")
	}
	if cc.Database != cfg.Database.Name || cc.Host != "10.203.11.11" || cc.User != "cloud8021x_task11_green_migrate" {
		return out, errors.New("fixed private SQL identity differs")
	}
	cc.TLSConfig, err = postgres.VerifiedTLSConfig(cfg.Database, cc.Host)
	if err != nil {
		return out, err
	}
	cc.Fallbacks = nil
	cc.ConnectTimeout = 5 * time.Second
	cc.RuntimeParams = map[string]string{"application_name": "task11-read-only-projection", "statement_timeout": "5000", "lock_timeout": "5000", "idle_in_transaction_session_timeout": "10000"}
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		return out, errors.New("private projection database unavailable")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = conn.Close(cleanup)
	}()
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return out, errors.New("read-only snapshot unavailable")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	s := &out.Snapshot
	if err = tx.QueryRow(ctx, `SELECT current_database(),e.deployment,e.transition,e.epoch,e.manifest_sha256,t.enabled,t.blocked,(SELECT count(*) FROM bootstrap_private.parallel_nodes n WHERE n.transition=e.transition AND n.ready) FROM ledger.collection_epoch e JOIN bootstrap_private.transitions t ON t.id=e.transition WHERE e.singleton`).Scan(&s.Database, &s.Deployment, &s.Transition, &s.Epoch, &s.Manifest, &out.Enabled, &out.Blocked, &out.Ready); err != nil {
		return out, errors.New("actual epoch/transition unavailable")
	}
	binding, err := adoption.ExpectedBinding(cfg, manifest.ApplicationSHA256)
	if err != nil || s.Database != cfg.Database.Name || s.Deployment != cfg.Deployment.ID || s.Transition != cfg.StateTransition || s.Manifest != binding.ManifestSHA256 || !s.Epoch.Equal(cfg.Deployment.CollectionEpoch) {
		return out, errors.New("actual SQL epoch/config/release binding differs")
	}
	rows, err := tx.Query(ctx, `SELECT w.id,w.kind,w.state,coalesce(w.owner,''),w.generation,w.payload,coalesce(w.receipt,'null'::jsonb),coalesce(a.receipt,'null'::jsonb),coalesce(a.outcome,''),coalesce(a.started_at,'epoch'::timestamptz),coalesce(a.finished_at,'epoch'::timestamptz),coalesce((SELECT o.receipt FROM bootstrap_private.operator_recovery r JOIN bootstrap_private.operator_recovery_outcomes o USING(request_id) WHERE r.request->>'WorkID'=w.id AND (r.request->>'Generation')::bigint=w.generation AND r.request->>'Mode'='fleet-terminal' AND o.outcome='terminal' ORDER BY r.created_at DESC LIMIT 1),'null'::jsonb) FROM ledger.work w LEFT JOIN ledger.attempts a ON a.work_id=w.id AND a.generation=w.generation WHERE w.kind='outbox' OR w.kind LIKE 'fleet-cert:%' ORDER BY w.id LIMIT 1153`)
	if err != nil {
		return out, errors.New("durable work snapshot unavailable")
	}
	budget := sqlRawLimit
	for rows.Next() {
		var w durableWork
		if err = rows.Scan(&w.ID, &w.Kind, &w.State, &w.Owner, &w.Generation, &w.Payload, &w.Receipt, &w.AttemptReceipt, &w.Outcome, &w.StartedAt, &w.FinishedAt, &w.RecoveryEvidence); err != nil {
			break
		}
		budget -= len(w.Payload) + len(w.Receipt) + len(w.AttemptReceipt) + len(w.RecoveryEvidence)
		if budget < 0 || len(s.Work) >= 1152 {
			err = errors.New("durable projection exceeds bounds")
			break
		}
		s.Work = append(s.Work, w)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return out, errors.New("bounded work snapshot failed")
	}
	rows, err = tx.Query(ctx, `SELECT id,source,host_uuid,state,observation,document,coalesce(evidence,'null'::bytea) FROM ledger.legacy_collection_guards ORDER BY id LIMIT 129`)
	if err != nil {
		return out, errors.New("original guards unavailable")
	}
	for rows.Next() {
		var g durableGuard
		var h, c []byte
		if err = rows.Scan(&g.ID, &g.Source, &g.HostUUID, &g.State, &h, &c, &g.Evidence); err != nil {
			break
		}
		budget -= len(h) + len(c) + len(g.Evidence)
		if budget < 0 || len(s.Guards) >= 128 || domain.DecodeJSONStrict(h, &g.Host) != nil || domain.DecodeJSONStrict(c, &g.Command) != nil {
			err = errors.New("original guard bound/codec failed")
			break
		}
		s.Guards = append(s.Guards, g)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return out, errors.New("original guard snapshot failed")
	}
	if err = tx.Commit(ctx); err != nil {
		return out, errors.New("read-only snapshot did not finish")
	}
	accounts, err := host.ReadAccounts()
	if err != nil {
		return out, err
	}
	raw, err := readPublishedSnapshot(cfg.Paths.InventoryFile, accounts.RuntimeUID)
	if err != nil {
		return out, err
	}
	defer clear(raw)
	out.InventorySHA256 = adoption.Digest(raw)
	snapshot, err := domain.DecodeSnapshot(bytes.NewReader(raw))
	if err != nil {
		return out, err
	}
	out.DisplaySHA256, err = semanticDisplay(cfg, snapshot)
	if err != nil {
		return out, err
	}
	if project {
		store := &domain.SnapshotStore{}
		if err = store.Set(snapshot); err != nil {
			return out, err
		}
		out.Records, out.Outbox, err = projectOutbox(*s, telemetry.NewDisplay(cfg, store, nil))
		if err != nil {
			return out, err
		}
	}
	return out, nil
}
func writeSQLObservation(ctx context.Context, project bool, out interface{ Write([]byte) (int, error) }) error {
	v, err := observeSQL(ctx, project)
	if err != nil {
		return err
	}
	return encodeSQLObservation(out, v)
}
