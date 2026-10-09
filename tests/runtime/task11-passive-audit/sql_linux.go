//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-passive-audit/contract"
	"github.com/jackc/pgx/v5"
)

func expectedBinding(c config.Config, r contract.Request) (adoption.Binding, error) {
	return adoption.ExpectedBinding(c, r.ApplicationSHA256)
}

// No writer/advisory lock or maintenance capability is acquired. Every query is
// fixed in source and executes within a repeatable-read READ ONLY transaction.
func observeSQL(ctx context.Context, c config.Config, r contract.Request, m contract.Manifest) (out contract.SQL, err error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	dsn, _, e := readProtected(fileRule{path: c.Database.MigrationDSN.File, uid: 0, gid: 0, mode: 0600, max: 64 << 10})
	if e != nil {
		return out, errors.New("protected migration credential unavailable")
	}
	defer clear(dsn)
	cc, e := pgx.ParseConfig(strings.TrimSpace(string(dsn)))
	if e != nil || cc.Host != "10.203.11.11" || cc.Port != 5432 || cc.Database != "cloud8021x_task11_green" || cc.User != "cloud8021x_task11_green_migrate" {
		return out, errors.New("fixed synthetic SQL peer/role differs")
	}
	cc.TLSConfig, e = postgres.VerifiedTLSConfig(c.Database, cc.Host)
	if e != nil {
		return out, e
	}
	cc.Fallbacks = nil
	cc.ConnectTimeout = 3 * time.Second
	cc.RuntimeParams = map[string]string{"application_name": "task11-passive-audit", "default_transaction_read_only": "on", "statement_timeout": "3000", "lock_timeout": "3000", "idle_in_transaction_session_timeout": "5000"}
	conn, e := pgx.ConnectConfig(ctx, cc)
	if e != nil {
		return out, errors.New("actual protected SQL connection unavailable")
	}
	defer func() {
		closeCtx, done := context.WithTimeout(context.Background(), time.Second)
		defer done()
		if conn.Close(closeCtx) != nil && err == nil {
			err = errors.New("read-only SQL connection did not close")
		}
	}()
	tx, e := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if e != nil {
		return out, e
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var readOnly, isolation string
	if tx.QueryRow(ctx, `SELECT current_setting('transaction_read_only'),current_setting('transaction_isolation')`).Scan(&readOnly, &isolation) != nil || readOnly != "on" || isolation != "repeatable read" {
		return out, errors.New("actual SQL read-only isolation unavailable")
	}
	e = tx.QueryRow(ctx, `SELECT current_database(),e.deployment,e.transition,e.epoch,e.manifest_sha256,t.enabled,t.blocked,ledger.workers_allowed(e.transition),(SELECT count(*) FROM bootstrap_private.parallel_nodes n WHERE n.transition=e.transition AND n.ready) FROM ledger.collection_epoch e JOIN bootstrap_private.transitions t ON t.id=e.transition WHERE e.singleton`).Scan(&out.Database, &out.Deployment, &out.Transition, &out.Epoch, &out.ManifestSHA256, &out.Enabled, &out.Blocked, &out.WorkersAllowed, &out.Ready)
	if e != nil {
		return out, errors.New("actual collection epoch/transition unavailable")
	}
	binding, e := expectedBinding(c, r)
	if e != nil || out.Transition != c.StateTransition || out.ManifestSHA256 != binding.ManifestSHA256 || !out.Epoch.Equal(c.Deployment.CollectionEpoch) {
		return out, errors.New("actual epoch binding differs")
	}
	for i, query := range []string{`SELECT node,config_sha256,receipt_sha256 FROM bootstrap_private.writer_fences WHERE transition=$1 ORDER BY node LIMIT 3`, `SELECT node,'',receipt_sha256 FROM bootstrap_private.worker_fences WHERE transition=$1 ORDER BY node LIMIT 3`} {
		rows, e := tx.Query(ctx, query, c.StateTransition)
		if e != nil {
			return out, errors.New("actual protected fence state unavailable")
		}
		fences := []contract.Fence{}
		for rows.Next() {
			var f contract.Fence
			if rows.Scan(&f.Node, &f.ConfigSHA256, &f.ReceiptSHA256) != nil {
				rows.Close()
				return out, errors.New("fence row malformed")
			}
			fences = append(fences, f)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return out, e
		}
		if i == 0 {
			out.WriterFences = fences
		} else {
			out.WorkerFences = fences
		}
	}
	rows, e := tx.Query(ctx, `SELECT role,instance,manifest,config,release_sha256,source_digest,authorization_document,prepared_receipt,trust_sha256,ready FROM bootstrap_private.parallel_nodes WHERE transition=$1 ORDER BY role LIMIT 3`, c.StateTransition)
	if e != nil {
		return out, errors.New("actual protected preparation state unavailable")
	}
	documents := []string{}
	var sharedClass, sharedTrust string
	for rows.Next() {
		var n contract.PreparedNode
		var manifest string
		var raw []byte
		if rows.Scan(&n.Role, &n.Instance, &manifest, &n.ConfigSHA256, &n.ReleaseSHA256, &n.SourceSHA256, &raw, &n.Receipt, &n.TrustSHA256, &n.Ready) != nil || len(raw) > adoption.MaxBytes {
			rows.Close()
			return out, errors.New("prepared record malformed or unbounded")
		}
		var doc adoption.Authorization
		e = domain.DecodeJSONStrict(raw, &doc)
		docDigest := digest(raw)
		clear(raw)
		source := c.Deployment.SourcePrimary
		if n.Role == "radius-secondary" {
			source = c.Deployment.SourceSecondary
		}
		if e != nil || doc.Native != nil || manifest != binding.ManifestSHA256 || n.ReleaseSHA256 != r.ApplicationSHA256 || n.Instance != c.Deployment.ID+strings.TrimPrefix(n.Role, "radius") || doc.Binding.Transition != c.StateTransition || doc.Binding.ManifestSHA256 != manifest || doc.Binding.ConfigSHA256 != n.ConfigSHA256 || doc.Binding.ReleaseSHA256 != n.ReleaseSHA256 || doc.Binding.Role != n.Role || doc.Binding.Instance != n.Instance || doc.Binding.SourceDeployment != c.Deployment.SourceID || doc.Binding.SourceInstance != source || doc.Binding.Deployment != c.Deployment.ID || !doc.Binding.CollectionEpoch.Equal(c.Deployment.CollectionEpoch) || doc.TrustSHA256 != n.TrustSHA256 || doc.ClassSHA256 != m.Slots["class-key"] || n.TrustSHA256 != m.Slots["client-trust"] || doc.CapturedAt.IsZero() {
			rows.Close()
			return out, errors.New("actual imported authorization binding differs")
		}
		matchedFence := false
		for _, f := range out.WriterFences {
			if f.Node == n.Role && f.ReceiptSHA256 == doc.FenceSHA256 && f.ConfigSHA256 == doc.SourceConfigSHA256 {
				matchedFence = true
			}
		}
		if !matchedFence {
			rows.Close()
			return out, errors.New("imported authorization differs from original writer fence")
		}
		if n.Role == c.InstanceID && n.ConfigSHA256 != binding.ConfigSHA256 {
			rows.Close()
			return out, errors.New("local canonical preparation config differs")
		}
		n.CertificateStateSHA256 = digest(doc.Certificates)
		n.PolicySHA256 = digest(doc.Policy)
		clear(doc.Certificates)
		clear(doc.Policy)
		if n.CertificateStateSHA256 != m.CertificateStateSHA256 || (len(out.Prepared) > 0 && (sharedClass != doc.ClassSHA256 || sharedTrust != doc.TrustSHA256)) {
			rows.Close()
			return out, errors.New("preserved source certificate/Class/trust identity differs")
		}
		sharedClass = doc.ClassSHA256
		sharedTrust = doc.TrustSHA256
		out.Prepared = append(out.Prepared, n)
		documents = append(documents, docDigest)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	raw, _ := json.Marshal(documents)
	out.AuthorizationSHA256 = digest(raw)
	for i, q := range []string{`SELECT to_jsonb(w)::text FROM ledger.work w ORDER BY w.id LIMIT 4097`, `SELECT to_jsonb(a)::text FROM ledger.attempts a ORDER BY a.work_id,a.generation LIMIT 4097`, `SELECT to_jsonb(g)::text FROM ledger.legacy_collection_guards g ORDER BY g.id LIMIT 129`} {
		rows, e := tx.Query(ctx, q)
		if e != nil {
			return out, errors.New("actual durable read-only state unavailable")
		}
		values := []string{}
		budget := 24 << 20
		for rows.Next() {
			var value string
			if rows.Scan(&value) != nil || len(value) > budget {
				rows.Close()
				return out, errors.New("durable state exceeds bound")
			}
			budget -= len(value)
			values = append(values, value)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return out, e
		}
		encoded, _ := json.Marshal(values)
		h := digest(encoded)
		clear(encoded)
		switch i {
		case 0:
			out.WorkRows = len(values)
			out.WorkSHA256 = h
		case 1:
			out.AttemptRows = len(values)
			out.AttemptsSHA256 = h
		case 2:
			out.GuardRows = len(values)
			out.GuardsSHA256 = h
		}
	}
	if e = tx.Rollback(ctx); e != nil {
		return out, errors.New("read-only transaction cleanup failed")
	}
	return out, nil
}
