package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/events/auth"
)

func validateAuthQuarantine(r auth.MalformedRange) error {
	if len(r.Source) > 512 || !strings.Contains(r.Source, "/auth-") || r.Start < 0 || r.End != r.Start+int64(len(r.Data)) || r.End > r.FileSize || r.Inode == 0 || bundleDigest(r.Data) != r.SHA256 {
		return errors.New("invalid original malformed range evidence")
	}
	return auth.ValidateMalformedRange(r.Data)
}
func (s *Store) AuthQuarantineRecorded(ctx context.Context, r auth.MalformedRange) (bool, error) {
	if e := validateAuthQuarantine(r); e != nil {
		return false, e
	}
	var matches bool
	e := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bootstrap_private.auth_quarantine q JOIN ledger.auth_cursors c ON c.source=q.source WHERE q.source=$1 AND q.start_offset=$2 AND q.end_offset=$3 AND q.sha256=$4 AND q.original=$5 AND CASE WHEN c.cursor ~ '^[0-9]{1,19}$' THEN c.cursor::numeric >= $3 ELSE false END)`, r.Source, r.Start, r.End, r.SHA256, r.Data).Scan(&matches)
	return matches, safeError(e)
}

// QuarantineAuth preserves the exact invalid bytes and physical evidence while
// advancing only their original source cursor, atomically. No event is emitted.
func (s *Store) QuarantineAuth(ctx context.Context, r auth.MalformedRange) error {
	scope, ok := ctx.Value(maintenanceScopeKey{}).(*maintenanceScope)
	if !ok || scope.store != s || !scope.active.Load() {
		return errors.New("root malformed recovery scope required")
	}
	if e := validateAuthQuarantine(r); e != nil {
		return e
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	tx, e := s.begin(ctx)
	if e != nil {
		return safeError(e)
	}
	defer rollback(tx)
	if _, e = tx.Exec(ctx, `INSERT INTO ledger.auth_cursors(source,cursor) VALUES($1,'') ON CONFLICT DO NOTHING`, r.Source); e != nil {
		return safeError(e)
	}
	var current string
	if e = tx.QueryRow(ctx, `SELECT cursor FROM ledger.auth_cursors WHERE source=$1 FOR UPDATE`, r.Source).Scan(&current); e != nil {
		return safeError(e)
	}
	next := strconv.FormatInt(r.End, 10)
	if current == next {
		var same bool
		if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bootstrap_private.auth_quarantine WHERE source=$1 AND start_offset=$2 AND end_offset=$3 AND sha256=$4 AND original=$5)`, r.Source, r.Start, r.End, r.SHA256, r.Data).Scan(&same); e != nil {
			return safeError(e)
		}
		if same {
			return nil
		}
		return ErrCursorConflict
	}
	if current != r.Expected || (current != "" && current != strconv.FormatInt(r.Start, 10)) || (current == "" && r.Start != 0) {
		return ErrCursorConflict
	}
	var used int64
	if e = tx.QueryRow(ctx, `SELECT coalesce(sum(octet_length(original)),0) FROM bootstrap_private.auth_quarantine`).Scan(&used); e != nil {
		return safeError(e)
	}
	if used+int64(len(r.Data)) > 64<<20 {
		return errors.New("protected malformed range retention capacity exhausted")
	}
	evidence, e := json.Marshal(struct {
		Device, Inode uint64
		Size          int64
	}{r.Device, r.Inode, r.FileSize})
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO bootstrap_private.auth_quarantine(source,start_offset,end_offset,sha256,original,evidence) VALUES($1,$2,$3,$4,$5,$6)`, r.Source, r.Start, r.End, r.SHA256, r.Data, evidence); e != nil {
		return safeError(e)
	}
	if _, e = tx.Exec(ctx, `UPDATE ledger.auth_cursors SET cursor=$2,updated_at=clock_timestamp() WHERE source=$1`, r.Source, next); e != nil {
		return safeError(e)
	}
	if e = commit(ctx, tx); e != nil {
		return ErrUncertain
	}
	return nil
}
