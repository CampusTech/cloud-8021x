package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

type WriterFenceIdentity struct{ Transition, Node, ConfigSHA256 string }

func (i WriterFenceIdentity) Operation() (string, error) {
	if !transitionDigest.MatchString(i.Transition) || !transitionDigest.MatchString(i.ConfigSHA256) || (i.Node != "radius-primary" && i.Node != "radius-secondary") {
		return "", errors.New("invalid fixed writer identity")
	}
	sum := sha256.Sum256([]byte(i.Transition + "\x00" + i.Node + "\x00" + i.ConfigSHA256))
	return "state-fence:" + hex.EncodeToString(sum[:]), nil
}

// ResumeWriterFence resumes only the exact expired protected writer operation.
// The fixed root CLI callback holds the original-operation flock, validates all
// saved physical states and proves PID-start quiescence before its first write.
// This cannot reconcile any other maintenance operation or select another payload.
func (s *Store) ResumeWriterFence(ctx context.Context, id int64, identity WriterFenceIdentity, resume func(context.Context) (string, error)) error {
	operation, e := identity.Operation()
	if e != nil || id <= 0 || resume == nil {
		return errors.New("exact writer recovery required")
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return safeError(e)
	}
	defer rollback(tx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(8021,8)"); e != nil {
		return safeError(e)
	}
	var prior string
	if e = tx.QueryRow(ctx, `SELECT operation FROM bootstrap_private.maintenance WHERE id=$1 AND outcome IN ('started','uncertain') AND expires_at<clock_timestamp() FOR UPDATE`, id).Scan(&prior); e != nil || prior != operation {
		return errors.New("writer recovery attempt identity mismatch or still live")
	}
	var others bool
	if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bootstrap_private.maintenance WHERE id!=$1 AND outcome IN ('started','uncertain'))`, id).Scan(&others); e != nil {
		return safeError(e)
	}
	if others {
		return errors.New("another unresolved root operation blocks writer recovery")
	}
	if _, e = tx.Exec(ctx, `UPDATE bootstrap_private.maintenance SET outcome='started',expires_at=clock_timestamp()+interval '30 seconds' WHERE id=$1`, id); e != nil {
		return safeError(e)
	}
	if e = commit(ctx, tx); e != nil {
		return ErrUncertain
	}
	return (MaintenanceGate{Store: s}).runAttempt(ctx, id, 30*time.Second, func(ctx context.Context) error {
		receipt, e := resume(ctx)
		if e != nil {
			return e
		}
		return s.RecordWriterFence(ctx, identity.Transition, identity.Node, identity.ConfigSHA256, receipt)
	})
}
