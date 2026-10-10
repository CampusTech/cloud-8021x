package postgres

import (
	"context"
	"errors"
	"time"
)

type WorkerFenceIdentity struct{ WriterFenceIdentity }

func (i WorkerFenceIdentity) Operation() (string, error) {
	base, e := i.WriterFenceIdentity.Operation()
	if e != nil {
		return "", e
	}
	return "state-export-fence:" + bundleDigest([]byte(base)), nil
}

func (s *Store) WorkerFenceAttempt(ctx context.Context, i WorkerFenceIdentity) (int64, error) {
	operation, e := i.Operation()
	if e != nil {
		return 0, e
	}
	scope, ok := ctx.Value(maintenanceScopeKey{}).(*maintenanceScope)
	if !ok || scope.store != s || !scope.active.Load() {
		return 0, errors.New("live worker fence scope required")
	}
	var matches bool
	if e = s.pool.QueryRow(ctx, `SELECT operation=$2 AND outcome='started' AND expires_at>clock_timestamp() FROM bootstrap_private.maintenance WHERE id=$1`, scope.id, operation).Scan(&matches); e != nil || !matches {
		return 0, errors.New("worker fence scope identity differs")
	}
	return scope.id, nil
}

// ResumeWorkerFence is deliberately separate from read-only reconciliation and
// publication import. Its only fixed root callback completes the saved cold
// export fence; the original flock/PID/unit/producer checks precede every write.
func (s *Store) ResumeWorkerFence(ctx context.Context, id int64, i WorkerFenceIdentity, resume func(context.Context) (string, []byte, error)) error {
	op, e := i.Operation()
	if e != nil || id <= 0 || resume == nil {
		return errors.New("exact cold worker fence required")
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return safeError(e)
	}
	defer rollback(tx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(8021,8)"); e != nil {
		return safeError(e)
	}
	var operation string
	if e = tx.QueryRow(ctx, `SELECT operation FROM bootstrap_private.maintenance WHERE id=$1 AND outcome IN ('started','uncertain') AND expires_at<clock_timestamp() FOR UPDATE`, id).Scan(&operation); e != nil || operation != op {
		return errors.New("worker recovery does not match expired original attempt")
	}
	var blocked, other bool
	if e = tx.QueryRow(ctx, `SELECT blocked AND NOT enabled FROM bootstrap_private.transitions WHERE id=$1 FOR UPDATE`, i.Transition).Scan(&blocked); e != nil || !blocked {
		return errors.New("original transition not revoked")
	}
	if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bootstrap_private.maintenance WHERE id!=$1 AND outcome IN ('started','uncertain'))`, id).Scan(&other); e != nil {
		return safeError(e)
	}
	if other {
		return errors.New("other root operation unresolved")
	}
	if _, e = tx.Exec(ctx, `INSERT INTO bootstrap_private.maintenance_recoveries(attempt,operation) VALUES($1,$2)`, id, op); e != nil {
		return safeError(e)
	}
	if _, e = tx.Exec(ctx, `UPDATE bootstrap_private.maintenance SET outcome='started',expires_at=clock_timestamp()+interval '30 seconds' WHERE id=$1`, id); e != nil {
		return safeError(e)
	}
	if e = commit(ctx, tx); e != nil {
		return ErrUncertain
	}
	return (MaintenanceGate{Store: s}).runAttempt(ctx, id, 30*time.Second, func(ctx context.Context) error {
		receipt, state, e := resume(ctx)
		if e != nil {
			return e
		}
		return s.RecordWorkerState(ctx, i.Transition, receipt, state)
	})
}
