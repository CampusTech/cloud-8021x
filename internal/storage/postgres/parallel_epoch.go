package postgres

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func createParallelEpoch(ctx context.Context, tx pgx.Tx, r Roles) error {
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS ledger.collection_epoch(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),deployment text NOT NULL,transition text NOT NULL,epoch timestamptz NOT NULL,manifest_sha256 text NOT NULL)`,
		`REVOKE ALL ON ledger.collection_epoch FROM PUBLIC,` + pgx.Identifier{r.Runtime}.Sanitize() + `,` + pgx.Identifier{r.Native}.Sanitize(),
		`GRANT SELECT ON ledger.collection_epoch TO ` + pgx.Identifier{r.Runtime}.Sanitize(),
	} {
		if _, err := tx.Exec(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

// PrepareCollectionEpoch is immutable and requires the protected maintenance
// scope. It never imports checkpoints, historical sessions, or the old outbox.
func (s *Store) PrepareCollectionEpoch(ctx context.Context, deployment, id, manifest string, epoch time.Time) error {
	scope, ok := ctx.Value(maintenanceScopeKey{}).(*maintenanceScope)
	if !ok || scope.store != s || !scope.active.Load() || !transitionDigest.MatchString(id) || !transitionDigest.MatchString(manifest) || epoch.IsZero() || epoch.Nanosecond() != 0 || s.databaseName != "cloud8021x_"+strings.ReplaceAll(deployment, "-", "_") {
		return errors.New("protected deployment-bound collection epoch required")
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return safeError(err)
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, `LOCK TABLE ledger.collection_epoch,ledger.intake,ledger.sessions,ledger.work IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return safeError(err)
	}
	var existingDeployment, existingID, existingManifest string
	var existingEpoch time.Time
	err = tx.QueryRow(ctx, `SELECT deployment,transition,manifest_sha256,epoch FROM ledger.collection_epoch WHERE singleton`).Scan(&existingDeployment, &existingID, &existingManifest, &existingEpoch)
	if err == nil {
		if existingDeployment != deployment || existingID != id || existingManifest != manifest || !existingEpoch.Equal(epoch) {
			return errors.New("collection epoch is immutable")
		}
		return safeError(commit(ctx, tx))
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return safeError(err)
	}
	var empty bool
	if err = tx.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM ledger.intake) AND NOT EXISTS(SELECT 1 FROM ledger.sessions) AND NOT EXISTS(SELECT 1 FROM ledger.observations) AND NOT EXISTS(SELECT 1 FROM ledger.intervals) AND NOT EXISTS(SELECT 1 FROM ledger.work) AND NOT EXISTS(SELECT 1 FROM ledger.auth_cursors) AND NOT EXISTS(SELECT 1 FROM ledger.import_markers)`).Scan(&empty); err != nil {
		return safeError(err)
	}
	if !empty {
		return errors.New("parallel epoch refuses accounting or export history")
	}
	if _, err = tx.Exec(ctx, `INSERT INTO ledger.collection_epoch(deployment,transition,manifest_sha256,epoch) VALUES($1,$2,$3,$4)`, deployment, id, manifest, epoch); err != nil {
		return safeError(err)
	}
	return safeError(commit(ctx, tx))
}
