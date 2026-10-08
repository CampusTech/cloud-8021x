package postgres

import (
	"context"
	"errors"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
)

// MaintenanceGate is exclusively constructed with the migration role. Its state
// is outside ledger and cannot be modified by daemon/native roles. A started
// attempt NEVER becomes eligible merely because its lease expires: loss of its
// heartbeat or any ambiguous external operation requires explicit reconciliation.
type MaintenanceGate struct {
	Store *Store
	Lease time.Duration
}

type maintenanceScopeKey struct{}
type maintenanceScope struct {
	id     int64
	store  *Store
	active atomic.Bool
}

func (g MaintenanceGate) With(ctx context.Context, operation string, fn func(context.Context) error) error {
	if g.Store == nil || operation == "" || len(operation) > 128 || fn == nil {
		return errors.New("invalid maintenance operation")
	}
	if scope, ok := ctx.Value(maintenanceScopeKey{}).(*maintenanceScope); ok {
		if scope.store != g.Store || !scope.active.Load() || ctx.Err() != nil {
			return errors.New("inactive or foreign maintenance scope")
		}
		return fn(ctx)
	}
	lease := g.Lease
	if lease == 0 {
		lease = 30 * time.Second
	}
	if lease < time.Second || lease > time.Minute {
		return errors.New("invalid maintenance lease")
	}
	tx, e := g.Store.begin(ctx)
	if e != nil {
		return safeError(e)
	}
	defer rollback(tx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(8021,8)"); e != nil {
		return safeError(e)
	}
	var busy bool
	if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bootstrap_private.maintenance WHERE outcome IN ('started','uncertain'))`).Scan(&busy); e != nil {
		return safeError(e)
	}
	if busy {
		return errors.New("unresolved root maintenance blocks changes; read-only reconciliation required")
	}
	var id int64
	if e = tx.QueryRow(ctx, `INSERT INTO bootstrap_private.maintenance(operation,expires_at,outcome) VALUES($1,clock_timestamp()+$2::interval,'started') RETURNING id`, operation, lease.String()).Scan(&id); e != nil {
		return safeError(e)
	}
	if e = commit(ctx, tx); e != nil {
		return errors.New("maintenance start uncertain; no external action attempted")
	}
	return g.runAttempt(ctx, id, lease, fn)
}
func (g MaintenanceGate) runAttempt(ctx context.Context, id int64, lease time.Duration, fn func(context.Context) error) error {
	scope := &maintenanceScope{store: g.Store, id: id}
	scope.active.Store(true)
	defer scope.active.Store(false)
	run, cancel := context.WithCancel(context.WithValue(ctx, maintenanceScopeKey{}, scope))
	defer cancel()
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(lease / 3)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-run.Done():
				return
			case <-ticker.C:
				qctx, qcancel := context.WithTimeout(run, lease/3)
				tag, err := g.Store.pool.Exec(qctx, `UPDATE bootstrap_private.maintenance SET expires_at=clock_timestamp()+$2::interval WHERE id=$1 AND outcome='started' AND expires_at>clock_timestamp()`, id, lease.String())
				qcancel()
				if err != nil || tag.RowsAffected() != 1 {
					cancel()
					return
				}
			}
		}
	}()
	actionError := fn(run)
	close(done)
	wg.Wait()
	if actionError != nil || run.Err() != nil {
		qctx, qcancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer qcancel()
		_, _ = g.Store.pool.Exec(qctx, `UPDATE bootstrap_private.maintenance SET outcome='uncertain' WHERE id=$1 AND outcome='started'`, id)
		return errors.New("root maintenance incomplete or uncertain; subsequent changes blocked")
	}
	tag, e := g.Store.pool.Exec(ctx, `UPDATE bootstrap_private.maintenance SET outcome='complete',finished_at=clock_timestamp() WHERE id=$1 AND outcome='started' AND expires_at>clock_timestamp()`, id)
	if e != nil || tag.RowsAffected() != 1 {
		return errors.New("maintenance completion uncertain; subsequent changes blocked")
	}
	return nil
}

// ReconcileMaintenance accepts a fixed caller's read-only evidence verifier, not
// user supplied SQL or paths. Only an expired/uncertain attempt can be resolved.
// The verifier must inspect external state, not retry the mutation.
type MaintenanceEvidence struct{ Operation, Installation string }

func (s *Store) ReconcileMaintenance(ctx context.Context, id int64, verify func(context.Context, MaintenanceEvidence) error) error {
	tx, e := s.begin(ctx)
	if e != nil {
		return safeError(e)
	}
	defer rollback(tx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(8021,8)"); e != nil {
		return safeError(e)
	}
	var evidence MaintenanceEvidence
	if e = tx.QueryRow(ctx, `SELECT operation,installation FROM bootstrap_private.maintenance WHERE id=$1 AND outcome IN ('started','uncertain') AND expires_at<clock_timestamp() FOR UPDATE`, id).Scan(&evidence.Operation, &evidence.Installation); e != nil {
		return errors.New("maintenance attempt not eligible for reconciliation")
	}
	if verify == nil || verify(ctx, evidence) != nil {
		return errors.New("maintenance reconciliation evidence rejected")
	}
	if _, e = tx.Exec(ctx, `UPDATE bootstrap_private.maintenance SET outcome='reconciled',finished_at=clock_timestamp() WHERE id=$1`, id); e != nil {
		return safeError(e)
	}
	return safeError(commit(ctx, tx))
}
func createMaintenance(ctx context.Context, tx pgx.Tx, r Roles) error {
	statements := []string{`CREATE SCHEMA IF NOT EXISTS bootstrap_private`, `REVOKE ALL ON SCHEMA bootstrap_private FROM PUBLIC,` + pgx.Identifier{r.Runtime}.Sanitize() + `,` + pgx.Identifier{r.Native}.Sanitize(), `CREATE TABLE IF NOT EXISTS bootstrap_private.maintenance(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,operation text NOT NULL,installation text NOT NULL DEFAULT '',started_at timestamptz NOT NULL DEFAULT clock_timestamp(),expires_at timestamptz NOT NULL,finished_at timestamptz,outcome text NOT NULL CHECK(outcome IN ('started','uncertain','complete','reconciled')))`, `CREATE TABLE IF NOT EXISTS bootstrap_private.ca_publication(reference text PRIMARY KEY CHECK(reference ~ '^[0-9a-f]{64}$'),secret text NOT NULL,sha256 text NOT NULL CHECK(sha256 ~ '^[0-9a-f]{64}$'),version text NOT NULL DEFAULT '',published boolean NOT NULL DEFAULT false)`, `REVOKE ALL ON ALL TABLES IN SCHEMA bootstrap_private FROM PUBLIC,` + pgx.Identifier{r.Runtime}.Sanitize() + `,` + pgx.Identifier{r.Native}.Sanitize(), `REVOKE ALL ON ALL SEQUENCES IN SCHEMA bootstrap_private FROM PUBLIC,` + pgx.Identifier{r.Runtime}.Sanitize() + `,` + pgx.Identifier{r.Native}.Sanitize()}
	for _, q := range statements {
		if _, e := tx.Exec(ctx, q); e != nil {
			return e
		}
	}
	var valid bool
	if e := tx.QueryRow(ctx, `SELECT n.nspowner=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND NOT EXISTS(SELECT 1 FROM pg_class c WHERE c.relnamespace=n.oid AND c.relowner<>n.nspowner) FROM pg_namespace n WHERE n.nspname='bootstrap_private'`).Scan(&valid); e != nil {
		return e
	}
	if !valid {
		return errors.New("bootstrap private schema or object ownership rejected")
	}
	return nil
}

// RecordInstallation binds a local durable LKG receipt to the live shared root
// operation. Callers cannot record a plan outside the gate's owned context.
func (s *Store) RecordInstallation(ctx context.Context, reference string) error {
	scope, ok := ctx.Value(maintenanceScopeKey{}).(*maintenanceScope)
	if !ok || scope.store != s || !scope.active.Load() || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(reference) {
		return errors.New("owned maintenance installation reference required")
	}
	tag, e := s.pool.Exec(ctx, `UPDATE bootstrap_private.maintenance SET installation=$2 WHERE id=$1 AND outcome='started' AND expires_at>clock_timestamp() AND (installation='' OR installation=$2)`, scope.id, reference)
	if e != nil {
		return safeError(e)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("installation plan fencing failed")
	}
	return nil
}

// CheckCAIsolation verifies preservation of the legacy stepca account and denies
// application/native roles CONNECT and TEMP on either CA database. Installation
// refuses unsafe existing ACLs; it does not guess new CA database ownership.
func (s *Store) CheckCAIsolation(ctx context.Context, r Roles) error {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	var valid bool
	e := s.pool.QueryRow(ctx, `SELECT count(*)=2 AND bool_and(has_database_privilege('stepca',oid,'CONNECT') AND NOT has_database_privilege($1,oid,'CONNECT,TEMP') AND NOT has_database_privilege($2,oid,'CONNECT,TEMP')) FROM pg_database WHERE datname IN ('stepca','stepca_rsa')`, r.Runtime, r.Native).Scan(&valid)
	if e != nil {
		return safeError(e)
	}
	if !valid {
		return errors.New("CA database isolation or preserved stepca access rejected")
	}
	return nil
}
