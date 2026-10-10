package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/config"
)

func ParallelPrepareOperation(c config.Config) string {
	raw, _ := json.Marshal(c)
	return "parallel-prepare:" + adoption.Digest(raw)
}

// ResumeParallelPrepare resumes only this expired passive preparation, while
// the fixed host callback proves original helper death and exact local receipt.
// A partial installation rolls back; a fully committed one is acknowledged.
func (s *Store) ResumeParallelPrepare(ctx context.Context, id int64, c config.Config, prove func(context.Context, string) (string, string, error)) error {
	if !c.Parallel() || id <= 0 || prove == nil {
		return errors.New("exact passive preparation recovery required")
	}
	operation := ParallelPrepareOperation(c)
	tx, err := s.begin(ctx)
	if err != nil {
		return safeError(err)
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(8021,8)"); err != nil {
		return safeError(err)
	}
	var prior, reference string
	if err = tx.QueryRow(ctx, `SELECT operation,installation FROM bootstrap_private.maintenance WHERE id=$1 AND outcome IN ('started','uncertain') AND expires_at<clock_timestamp() FOR UPDATE`, id).Scan(&prior, &reference); err != nil || prior != operation {
		return errors.New("preparation recovery differs from expired original attempt")
	}
	var other bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bootstrap_private.maintenance WHERE id!=$1 AND outcome IN ('started','uncertain')) OR EXISTS(SELECT 1 FROM bootstrap_private.transitions WHERE id=$2 AND (enabled OR blocked))`, id, c.StateTransition).Scan(&other); err != nil {
		return safeError(err)
	}
	if other {
		return errors.New("another unresolved operation or active/revoked epoch blocks preparation recovery")
	}
	if _, err = tx.Exec(ctx, `INSERT INTO bootstrap_private.maintenance_recoveries(attempt,operation) VALUES($1,$2)`, id, operation); err != nil {
		return safeError(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE bootstrap_private.maintenance SET outcome='started',expires_at=clock_timestamp()+interval '30 seconds' WHERE id=$1`, id); err != nil {
		return safeError(err)
	}
	if err = commit(ctx, tx); err != nil {
		return ErrUncertain
	}
	return (MaintenanceGate{Store: s}).runAttempt(ctx, id, 30*time.Second, func(ctx context.Context) error {
		receipt, trust, err := prove(ctx, reference)
		if err != nil {
			return err
		}
		if receipt == "" {
			return nil
		}
		if receipt != reference {
			return errors.New("physical preparation receipt differs from original shared attempt")
		}
		return s.RecordParallelPrepared(ctx, c, receipt, trust)
	})
}

func ParallelActivateOperation(c config.Config) string {
	raw, _ := json.Marshal(c)
	return "parallel-activate:" + adoption.Digest(raw)
}

// ResumeParallelActivation retains the original typed operation and enables no
// bypass of source signatures, peer readiness, physical receipt, or epoch gates.
func (s *Store) ResumeParallelActivation(ctx context.Context, id int64, c config.Config, resume func(context.Context) error) error {
	if !c.Parallel() || id <= 0 || resume == nil {
		return errors.New("exact parallel activation recovery required")
	}
	operation := ParallelActivateOperation(c)
	tx, err := s.begin(ctx)
	if err != nil {
		return safeError(err)
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(8021,8)"); err != nil {
		return safeError(err)
	}
	var prior string
	if err = tx.QueryRow(ctx, `SELECT operation FROM bootstrap_private.maintenance WHERE id=$1 AND installation='' AND outcome IN ('started','uncertain') AND expires_at<clock_timestamp() FOR UPDATE`, id).Scan(&prior); err != nil || prior != operation {
		return errors.New("activation recovery differs from expired original attempt")
	}
	var other bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bootstrap_private.maintenance WHERE id!=$1 AND outcome IN ('started','uncertain'))`, id).Scan(&other); err != nil {
		return safeError(err)
	}
	if other {
		return errors.New("another unresolved operation blocks activation recovery")
	}
	if _, err = tx.Exec(ctx, `INSERT INTO bootstrap_private.maintenance_recoveries(attempt,operation) VALUES($1,$2)`, id, operation); err != nil {
		return safeError(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE bootstrap_private.maintenance SET outcome='started',expires_at=clock_timestamp()+interval '30 seconds' WHERE id=$1`, id); err != nil {
		return safeError(err)
	}
	if err = commit(ctx, tx); err != nil {
		return ErrUncertain
	}
	return (MaintenanceGate{Store: s}).runAttempt(ctx, id, 30*time.Second, resume)
}

func (s *Store) ResetParallelReadiness(ctx context.Context, c config.Config) error {
	scope, ok := ctx.Value(maintenanceScopeKey{}).(*maintenanceScope)
	if !ok || scope.store != s || !scope.active.Load() {
		return errors.New("protected passive readiness reset required")
	}
	raw, _ := json.Marshal(c)
	tag, err := s.pool.Exec(ctx, `UPDATE bootstrap_private.parallel_nodes n SET ready=false FROM bootstrap_private.transitions t WHERE n.transition=t.id AND t.id=$1 AND NOT t.enabled AND n.role=$2 AND n.config=$3`, c.StateTransition, c.InstanceID, adoption.Digest(raw))
	if err != nil {
		return safeError(err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("physical node is not in a passive epoch")
	}
	return nil
}
