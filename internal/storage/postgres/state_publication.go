package postgres

import (
	"context"
	"errors"
	"time"
)

type StatePublicationIdentity struct {
	WriterFenceIdentity
	BundleSHA256 string
}

func (i StatePublicationIdentity) Operation() (string, error) {
	base, e := i.WriterFenceIdentity.Operation()
	if e != nil || !transitionDigest.MatchString(i.BundleSHA256) {
		return "", errors.New("exact state publication identity required")
	}
	return "state-migrate:" + bundleDigest([]byte(base+":"+i.BundleSHA256)), nil
}
func (s *Store) StatePublicationAttempt(ctx context.Context, i StatePublicationIdentity) (int64, error) {
	op, e := i.Operation()
	if e != nil {
		return 0, e
	}
	scope, ok := ctx.Value(maintenanceScopeKey{}).(*maintenanceScope)
	if !ok || scope.store != s || !scope.active.Load() {
		return 0, errors.New("live publication scope required")
	}
	var matches bool
	if e = s.pool.QueryRow(ctx, `SELECT operation=$2 AND outcome='started' AND expires_at>clock_timestamp() FROM bootstrap_private.maintenance WHERE id=$1`, scope.id, op).Scan(&matches); e != nil || !matches {
		return 0, errors.New("publication scope identity differs")
	}
	return scope.id, nil
}
func (s *Store) RequireImportedBundle(ctx context.Context, i StatePublicationIdentity) error {
	if _, e := i.Operation(); e != nil {
		return e
	}
	var ready bool
	e := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bootstrap_private.legacy_bundles b JOIN ledger.import_markers m ON m.id='state:'||b.transition||':'||b.node WHERE b.transition=$1 AND b.node=$2 AND b.checksum=$3 AND m.checksum=b.checksum)`, i.Transition, i.Node, i.BundleSHA256).Scan(&ready)
	if e != nil {
		return safeError(e)
	}
	if !ready {
		return errors.New("original committed whole-bundle marker unavailable")
	}
	return nil
}

// ResumeStatePublication never re-imports or accepts a replacement document. It
// continues only exact local publication and acknowledgements of a known import.
// The fixed root caller holds its original-operation flock and proves the saved
// helper PID/start exited before invoking this method.
func (s *Store) ResumeStatePublication(ctx context.Context, id int64, i StatePublicationIdentity, resume func(context.Context) error) error {
	op, e := i.Operation()
	if e != nil || id <= 0 || resume == nil {
		return errors.New("exact publication recovery required")
	}
	if e = s.RequireNodeWriterFences(ctx, i.Transition, i.Node, i.ConfigSHA256); e != nil {
		return e
	}
	if e = s.RequireImportedBundle(ctx, i); e != nil {
		return e
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return safeError(e)
	}
	defer rollback(tx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(8021,8)"); e != nil {
		return safeError(e)
	}
	var old string
	if e = tx.QueryRow(ctx, `SELECT operation FROM bootstrap_private.maintenance WHERE id=$1 AND outcome IN ('started','uncertain') AND expires_at<clock_timestamp() FOR UPDATE`, id).Scan(&old); e != nil || old != op {
		return errors.New("publication attempt not exact expired original")
	}
	var other bool
	if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bootstrap_private.maintenance WHERE id!=$1 AND outcome IN ('started','uncertain'))`, id).Scan(&other); e != nil {
		return safeError(e)
	}
	if other {
		return errors.New("another root operation unresolved")
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
	return (MaintenanceGate{Store: s}).runAttempt(ctx, id, 30*time.Second, resume)
}

// EnableIfPublished is a single transaction under the live root heartbeat. A
// first node can finish successfully while the second remains safely fenced.
func (s *Store) EnableIfPublished(ctx context.Context, id string) (bool, error) {
	scope, ok := ctx.Value(maintenanceScopeKey{}).(*maintenanceScope)
	if !ok || scope.store != s || !scope.active.Load() {
		return false, errors.New("root publication scope required")
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return false, safeError(e)
	}
	defer rollback(tx)
	var ready bool
	if e = tx.QueryRow(ctx, `SELECT NOT blocked AND EXISTS(SELECT 1 FROM ledger.import_markers WHERE id='state:'||$1) FROM bootstrap_private.transitions WHERE id=$1 FOR UPDATE`, id).Scan(&ready); e != nil {
		return false, safeError(e)
	}
	if ready {
		tag, e := tx.Exec(ctx, `UPDATE bootstrap_private.transitions SET enabled=true WHERE id=$1 AND NOT blocked AND (SELECT count(*) FROM bootstrap_private.writer_fences WHERE transition=$1)=2`, id)
		if e != nil {
			return false, safeError(e)
		}
		if tag.RowsAffected() != 1 {
			return false, errors.New("both original fences required")
		}
	}
	if e = commit(ctx, tx); e != nil {
		return false, ErrUncertain
	}
	return ready, nil
}
