//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
	"github.com/jackc/pgx/v5"
)

type scenarioPGQuery struct{ tx pgx.Tx }

func (q scenarioPGQuery) Query(ctx context.Context, sql string, args ...any) (scenarioSQLRows, error) {
	return q.tx.Query(ctx, sql, args...)
}

// Snapshot retains checked parent/file descriptors and rejects symlinks,
// writable ancestry, non-root ownership and multiple links. Shipping config and
// PostgreSQL trust are explicitly0644; private incoming files remain0600.
func scenarioInstalledFile(path, pin string, mode uint32, limit int) error {
	saved, err := host.Snapshot(host.File{Path: path, UID: 0})
	defer clear(saved.Data)
	if err != nil || !saved.Exists || saved.UID != 0 || saved.Mode != mode || len(saved.Data) > limit || adoption.Digest(saved.Data) != pin {
		return errors.New("installed scenario file differs from protected shipping pin")
	}
	return nil
}
func scenarioNodeBinding(accounting bool) (config.Config, host.Manifest, error) {
	var empty host.Manifest
	if err := fixtureGuard(); err != nil {
		return config.Config{}, empty, err
	}
	cfg, manifest, err := nodeConfig()
	if err != nil {
		return cfg, manifest, errors.New("protected scenario configuration unavailable")
	}
	if cfg.Deployment.ID != "task11-green" || cfg.Database.Name != "cloud8021x_task11_green" || !neutralNetworkScope(cfg) || cfg.Database.CAFile != host.PostgresCAFile || cfg.Database.TLSMode != "cloudsql-instance-ca" || cfg.Database.InstanceCAPEMSHA256 != manifest.PostgresCASHA256 || cfg.Database.MigrationDSN.File != "/run/cloud-8021x-root/postgres-migration-dsn" || cfg.Bootstrap.ECDB.File != "/run/cloud-8021x-root/stepca-dsn" || cfg.Bootstrap.RSADB.File != "/run/cloud-8021x-root/stepca-rsa-dsn" {
		return cfg, manifest, errors.New("fixed private scenario configuration differs")
	}
	if accounting {
		if err = scenarioInstalledFile("/etc/cloud-8021x/config.yaml", manifest.ConfigSHA256, 0644, config.MaxConfigBytes); err != nil {
			return cfg, manifest, err
		}
	}
	// Both original and adopted nodes carry the same pinned application and PG
	// trust. Original installed config intentionally differs from staged green.
	if err = scenarioInstalledFile("/usr/local/bin/cloud-8021x", manifest.ApplicationSHA256, 0755, 256<<20); err != nil {
		return cfg, manifest, err
	}
	if err = scenarioInstalledFile(host.PostgresCAFile, manifest.PostgresCASHA256, 0644, 1<<20); err != nil {
		return cfg, manifest, err
	}
	ca, err := readPrivate(host.IncomingPostgresCAFile, 1<<20, 0)
	if err != nil {
		return cfg, manifest, errors.New("protected scenario PostgreSQL trust unavailable")
	}
	defer clear(ca)
	if adoption.Digest(ca) != manifest.PostgresCASHA256 {
		return cfg, manifest, errors.New("protected scenario PostgreSQL trust changed")
	}
	return cfg, manifest, nil
}
func scenarioOpenSnapshot(ctx context.Context, cfg config.Database, dsn []byte, user, database string) (*pgx.Conn, pgx.Tx, error) {
	cc, err := scenarioSQLCredential(dsn, cfg, user, database)
	if err != nil {
		return nil, nil, err
	}
	// Verify the exact0600 protected incoming copy of the same installed trust.
	// No DSN override can supply another trust root or disable verification.
	cfg.CAFile = host.IncomingPostgresCAFile
	cc.TLSConfig, err = postgres.VerifiedTLSConfig(cfg, cc.Host)
	if err != nil {
		return nil, nil, errors.New("verified private scenario TLS unavailable")
	}
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		return nil, nil, errors.New("private scenario database unavailable")
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		scenarioCloseSnapshot(conn, nil)
		return nil, nil, errors.New("read-only scenario snapshot unavailable")
	}
	var actualDatabase, actualUser, readOnly, isolation string
	if tx.QueryRow(ctx, `SELECT current_database(),current_user,current_setting('transaction_read_only'),current_setting('transaction_isolation')`).Scan(&actualDatabase, &actualUser, &readOnly, &isolation) != nil || actualDatabase != database || actualUser != user || readOnly != "on" || isolation != "repeatable read" {
		scenarioCloseSnapshot(conn, tx)
		return nil, nil, errors.New("actual scenario database identity or snapshot mode differs")
	}
	return conn, tx, nil
}
func scenarioCloseSnapshot(conn *pgx.Conn, tx pgx.Tx) {
	cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if tx != nil {
		_ = tx.Rollback(cleanup)
	}
	_ = conn.Close(cleanup)
}
func observeScenarioAccounting(ctx context.Context, sessions []string) (out scenariocontract.LedgerObservation, err error) {
	if _, err := scenarioSessionPatterns(sessions); err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := fixtureGuard(); err != nil {
		return out, err
	}
	unlock, err := host.AcquireWriterOperation()
	if err != nil {
		return out, errors.New("reserved scenario writer operation unavailable")
	}
	defer unlock()
	cfg, manifest, err := scenarioNodeBinding(true)
	if err != nil {
		return out, err
	}
	dsn, err := readPrivate(cfg.Database.MigrationDSN.File, 64<<10, 0)
	if err != nil {
		return out, errors.New("protected scenario SQL credential unavailable")
	}
	defer clear(dsn)
	conn, tx, err := scenarioOpenSnapshot(ctx, cfg.Database, dsn, "cloud8021x_task11_green_migrate", cfg.Database.Name)
	if err != nil {
		return out, err
	}
	defer scenarioCloseSnapshot(conn, tx)
	var database, deployment, transition, manifestSHA string
	var epoch time.Time
	// Existing shipping epoch/transition schema only; no invented inventory or
	// scenario readiness table. Rows are bound even while workers are blocked.
	if tx.QueryRow(ctx, `SELECT current_database(),e.deployment,e.transition,e.epoch,e.manifest_sha256 FROM ledger.collection_epoch e JOIN bootstrap_private.transitions t ON t.id=e.transition WHERE e.singleton`).Scan(&database, &deployment, &transition, &epoch, &manifestSHA) != nil {
		return out, errors.New("actual selected ledger epoch unavailable")
	}
	expected, err := adoption.ExpectedBinding(cfg, manifest.ApplicationSHA256)
	if err != nil || database != cfg.Database.Name || deployment != cfg.Deployment.ID || transition != cfg.StateTransition || manifestSHA != expected.ManifestSHA256 || !epoch.Equal(cfg.Deployment.CollectionEpoch) {
		return out, errors.New("actual selected ledger config/epoch binding differs")
	}
	out, err = readScenarioAccountingRows(ctx, scenarioPGQuery{tx}, sessions, scenarioLedgerBinding{deployment, database, manifest.ConfigSHA256, epoch})
	if err != nil {
		return out, err
	}
	if tx.Commit(ctx) != nil {
		return out, errors.New("read-only selected ledger snapshot did not finish")
	}
	return out, nil
}
func observeScenarioCA(ctx context.Context, selectionRaw []byte) (out scenariocontract.CAObservation, err error) {
	selection, err := scenariocontract.DecodeCASelection(selectionRaw)
	if err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := fixtureGuard(); err != nil {
		return out, err
	}
	unlock, err := host.AcquireWriterOperation()
	if err != nil {
		return out, errors.New("reserved scenario writer operation unavailable")
	}
	defer unlock()
	cfg, _, err := scenarioNodeBinding(false)
	if err != nil {
		return out, err
	}
	base, database, ref := "/etc/step-ca", "stepca", cfg.Bootstrap.ECDB.File
	if selection.Authority == "rsa" {
		base, database, ref = "/etc/step-ca-rsa", "stepca_rsa", cfg.Bootstrap.RSADB.File
	}
	dsn, err := readPrivate(ref, 64<<10, 0)
	if err != nil {
		return out, errors.New("protected inherited CA credential unavailable")
	}
	defer clear(dsn)
	raw, err := readPrivate(base+"/config/ca.json", 4<<20, 0)
	if err != nil {
		return out, errors.New("protected original CA configuration unavailable")
	}
	defer clear(raw)
	var object map[string]json.RawMessage
	var db struct {
		Type       string `json:"type"`
		DataSource string `json:"dataSource"`
	}
	var rootPath, intermediatePath string
	if decodeExactJSON(raw, &object) != nil || object == nil || decodeExactJSON(object["db"], &db) != nil || db.Type != "postgresql" || !bytes.Equal([]byte(db.DataSource), bytes.TrimSpace(dsn)) || json.Unmarshal(object["root"], &rootPath) != nil || json.Unmarshal(object["crt"], &intermediatePath) != nil || rootPath != base+"/certs/root_ca.crt" || intermediatePath != base+"/certs/intermediate_ca.crt" {
		return out, errors.New("original fixed CA database or chain references differ")
	}
	root, err := readPrivate(rootPath, 1<<20, 0)
	if err != nil {
		return out, errors.New("protected original CA root unavailable")
	}
	defer clear(root)
	intermediate, err := readPrivate(intermediatePath, 1<<20, 0)
	if err != nil {
		return out, errors.New("protected original CA intermediate unavailable")
	}
	defer clear(intermediate)
	dbCfg := cfg.Database
	dbCfg.Name = database
	conn, tx, err := scenarioOpenSnapshot(ctx, dbCfg, dsn, "stepca", database)
	if err != nil {
		return out, err
	}
	defer scenarioCloseSnapshot(conn, tx)
	out, err = readScenarioCARows(ctx, scenarioPGQuery{tx}, selectionRaw, root, intermediate)
	if err != nil {
		return out, err
	}
	if tx.Commit(ctx) != nil {
		return out, errors.New("read-only selected CA snapshot did not finish")
	}
	return out, nil
}
