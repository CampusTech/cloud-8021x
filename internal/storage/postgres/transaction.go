package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// Set the acknowledgment contract for every transaction even if a pooled
// connection previously had another setting. Commit reasserts it after imports.
func (s *Store) begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, "SET LOCAL synchronous_commit=on"); err != nil {
		rollback(tx)
		return nil, err
	}
	if s.transitionBound {
		var allowed bool
		if err = tx.QueryRow(ctx, "SELECT ledger.lock_worker_transition($1)", s.transition).Scan(&allowed); err != nil || !allowed {
			rollback(tx)
			if err != nil {
				return nil, err
			}
			return nil, errors.New("worker transition fenced")
		}
	}
	return tx, nil
}
func commit(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, "SET LOCAL synchronous_commit=on"); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
