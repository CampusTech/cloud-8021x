package postgres

import (
	"context"
	"errors"
	"strconv"

	"github.com/CampusTech/cloud-8021x/migrations"
	"github.com/jackc/pgx/v5"
)

func fmtInt(n int64) string { return strconv.FormatInt(n, 10) }

type Roles struct{ Runtime, Native string }

func (s *Store) CheckDurability(ctx context.Context) error {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	var fsync, full, sync, wal string
	if err := s.pool.QueryRow(ctx, "SELECT current_setting('fsync'),current_setting('full_page_writes'),current_setting('synchronous_commit'),current_setting('wal_level')").Scan(&fsync, &full, &sync, &wal); err != nil {
		return safeError(err)
	}
	if fsync != "on" || full != "on" || sync != "on" || (wal != "replica" && wal != "logical") {
		return errors.New("database durability configuration rejected")
	}
	return nil
}

// Migrate uses a separate privileged connection. Roles must already exist; it
// never creates credentials or modifies the CA database. PUBLIC CONNECT/TEMP
// must be revoked on the application AND CA databases by privileged bootstrap.
func (s *Store) Migrate(ctx context.Context, r Roles) error {
	if r.Runtime == "" || r.Native == "" || r.Runtime == r.Native {
		return errors.New("distinct database roles required")
	}
	if err := s.CheckDurability(ctx); err != nil {
		return err
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	tx, err := s.begin(ctx)
	if err != nil {
		return safeError(err)
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(8021,1)"); err != nil {
		return safeError(err)
	}
	var selectedDB string
	if err = tx.QueryRow(ctx, "SELECT current_database()").Scan(&selectedDB); err != nil {
		return safeError(err)
	}
	if selectedDB != "cloud8021x" {
		return errors.New("application migrations require the dedicated cloud8021x database")
	}
	var roleCount int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM pg_roles r WHERE rolname=ANY($1) AND rolname<>current_user AND NOT(rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls) AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid) AND NOT EXISTS(SELECT 1 FROM pg_database WHERE datdba=r.oid) AND NOT EXISTS(SELECT 1 FROM pg_namespace WHERE nspowner=r.oid) AND NOT EXISTS(SELECT 1 FROM pg_class WHERE relowner=r.oid)`, []string{r.Runtime, r.Native}).Scan(&roleCount); err != nil {
		return safeError(err)
	}
	if roleCount != 2 {
		return errors.New("runtime and native roles must be distinct unprivileged roles without memberships")
	}
	var exists bool
	if err = tx.QueryRow(ctx, "SELECT to_regclass('ledger.schema_version') IS NOT NULL").Scan(&exists); err != nil {
		return safeError(err)
	}
	v := 1
	if !exists {
		if _, err = tx.Exec(ctx, migrations.Ledger); err != nil {
			return safeError(err)
		}
	} else {
		if err = tx.QueryRow(ctx, "SELECT max(version) FROM ledger.schema_version").Scan(&v); err != nil {
			return safeError(err)
		}
		if v < 1 || v > migrations.Version {
			return errors.New("unsupported database schema version")
		}
	}
	if v == 1 {
		if _, err = tx.Exec(ctx, migrations.Collection); err != nil {
			return safeError(err)
		}
	}
	if v <= 2 {
		if _, err = tx.Exec(ctx, migrations.TerminationCause); err != nil {
			return safeError(err)
		}
	}
	var db string
	if err = tx.QueryRow(ctx, "SELECT current_database()").Scan(&db); err != nil {
		return safeError(err)
	}
	runtime, native := pgx.Identifier{r.Runtime}.Sanitize(), pgx.Identifier{r.Native}.Sanitize()
	grants := []string{
		"REVOKE ALL ON DATABASE " + pgx.Identifier{db}.Sanitize() + " FROM PUBLIC",
		"GRANT CONNECT ON DATABASE " + pgx.Identifier{db}.Sanitize() + " TO " + runtime + "," + native,
		"REVOKE CREATE ON SCHEMA public FROM PUBLIC",
		"REVOKE ALL ON DATABASE " + pgx.Identifier{db}.Sanitize() + " FROM " + runtime + "," + native,
		"GRANT CONNECT ON DATABASE " + pgx.Identifier{db}.Sanitize() + " TO " + runtime + "," + native,
		"REVOKE ALL ON ALL TABLES IN SCHEMA ledger FROM " + runtime + "," + native,
		"REVOKE ALL ON ALL SEQUENCES IN SCHEMA ledger FROM " + runtime + "," + native,
		"REVOKE ALL ON SCHEMA ledger FROM " + runtime + "," + native,
		"GRANT USAGE ON SCHEMA ledger TO " + runtime + "," + native,
		"GRANT SELECT ON ALL TABLES IN SCHEMA ledger TO " + runtime,
		"GRANT INSERT,UPDATE ON ledger.sessions,ledger.intake,ledger.work,ledger.attempts,ledger.auth_cursors TO " + runtime,
		"GRANT INSERT ON ledger.observations,ledger.intervals,ledger.quarantine,ledger.import_markers,ledger.reconciliations TO " + runtime,
		"GRANT USAGE ON ALL SEQUENCES IN SCHEMA ledger TO " + runtime,
		"GRANT INSERT ON ledger.intake TO " + native,
		"GRANT USAGE ON SEQUENCE ledger.intake_id_seq TO " + native,
		"GRANT EXECUTE ON FUNCTION ledger.session_key(text,text,integer,text,integer,text,integer) TO " + runtime + "," + native,
	}
	for _, q := range grants {
		if _, err = tx.Exec(ctx, q); err != nil {
			return safeError(err)
		}
	}
	return safeError(commit(ctx, tx))
}
func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 2e9)
	defer cancel()
	_ = tx.Rollback(ctx)
}
