package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
)

var ErrCursorConflict = errors.New("auth cursor changed concurrently")

// AuthEvent advances a native log cursor and writes its business outbox atomically.
// Expected empty means no previous cursor. Event IDs must be stable source+record
// identities; replay after a lost commit response resolves through Cursor.
func (s *Store) AuthEvent(ctx context.Context, source, expected, next, eventID string, payload json.RawMessage) error {
	if source == "" || next == "" || eventID == "" || !json.Valid(payload) || len(payload) > 1<<20 {
		return errors.New("invalid auth event")
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	tx, err := s.begin(ctx)
	if err != nil {
		return safeError(err)
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, "INSERT INTO ledger.auth_cursors(source,cursor) VALUES($1,'') ON CONFLICT(source) DO NOTHING", source); err != nil {
		return safeError(err)
	}
	var cursor string
	if err = tx.QueryRow(ctx, "SELECT cursor FROM ledger.auth_cursors WHERE source=$1 FOR UPDATE", source).Scan(&cursor); err != nil {
		return safeError(err)
	}
	if cursor == next {
		var exists bool
		if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM ledger.work WHERE id=$1 AND kind='outbox' AND payload=$2::jsonb)", "auth:"+eventID, []byte(payload)).Scan(&exists); err != nil {
			return safeError(err)
		}
		if exists {
			return nil
		}
		return ErrCursorConflict
	}
	if cursor != expected {
		return ErrCursorConflict
	}
	if err = enqueue(ctx, tx, "auth:"+eventID, "outbox", payload); err != nil {
		return safeError(err)
	}
	if _, err = tx.Exec(ctx, "UPDATE ledger.auth_cursors SET cursor=$2,updated_at=clock_timestamp() WHERE source=$1", source, next); err != nil {
		return safeError(err)
	}
	if err = commit(ctx, tx); err != nil {
		return ErrUncertain
	}
	return nil
}
func (s *Store) Cursor(ctx context.Context, source string) (string, error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	var cursor string
	err := s.pool.QueryRow(ctx, "SELECT cursor FROM ledger.auth_cursors WHERE source=$1", source).Scan(&cursor)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return cursor, safeError(err)
}

// AuthCursors bounds a quiescent root retention pass to one database query.
func (s *Store) AuthCursors(ctx context.Context, sources []string) (map[string]string, error) {
	out := map[string]string{}
	if len(sources) > 4096 {
		return nil, errors.New("auth cursor batch exceeds bound")
	}
	if len(sources) == 0 {
		return out, nil
	}
	for _, source := range sources {
		if source == "" || len(source) > 512 {
			return nil, errors.New("invalid auth cursor source")
		}
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	rows, e := s.pool.Query(ctx, `SELECT source,cursor FROM ledger.auth_cursors WHERE source=ANY($1)`, sources)
	if e != nil {
		return nil, safeError(e)
	}
	defer rows.Close()
	for rows.Next() {
		var source, cursor string
		if e = rows.Scan(&source, &cursor); e != nil {
			return nil, safeError(e)
		}
		out[source] = cursor
	}
	return out, safeError(rows.Err())
}
