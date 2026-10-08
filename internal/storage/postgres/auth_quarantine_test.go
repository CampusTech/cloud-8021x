package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/events/auth"
)

func TestPostgresMalformedRangeAtomicRetentionAndCursorRecovery(t *testing.T) {
	s, c := integration(t)
	ctx := context.Background()
	if _, e := s.pool.Exec(ctx, "TRUNCATE bootstrap_private.maintenance,bootstrap_private.auth_quarantine,ledger.auth_cursors,ledger.work CASCADE"); e != nil {
		t.Fatal(e)
	}
	raw := []byte("original native header\n\tPacket-Type = Access-Accept\n\tC8021X-Receipt = broken\n\n")
	r := auth.MalformedRange{Source: "radius-primary/auth-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-2026100810.detail", Start: 0, End: int64(len(raw)), FileSize: int64(len(raw)), Device: 1, Inode: 2, Data: raw, SHA256: bundleDigest(raw)}
	if e := s.QuarantineAuth(ctx, r); e == nil {
		t.Fatal("unprotected recovery accepted")
	}
	if _, e := s.pool.Exec(ctx, `CREATE FUNCTION ledger.fixture_reject_cursor() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture'; END $$; CREATE TRIGGER fixture_reject_cursor BEFORE UPDATE ON ledger.auth_cursors FOR EACH ROW EXECUTE FUNCTION ledger.fixture_reject_cursor()`); e != nil {
		t.Fatal(e)
	}
	gate := MaintenanceGate{Store: s}
	if e := gate.With(ctx, "fixture-quarantine-rollback", func(ctx context.Context) error {
		if e := s.QuarantineAuth(ctx, r); e == nil {
			t.Fatal("cursor failure accepted")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	var n int
	if e := s.pool.QueryRow(ctx, `SELECT count(*) FROM bootstrap_private.auth_quarantine`).Scan(&n); e != nil || n != 0 {
		t.Fatal("partial quarantine retained without cursor", n, e)
	}
	if cursor, e := s.Cursor(ctx, r.Source); e != nil || cursor != "" {
		t.Fatal("cursor advanced on rollback", cursor, e)
	}
	if _, e := s.pool.Exec(ctx, `DROP TRIGGER fixture_reject_cursor ON ledger.auth_cursors; DROP FUNCTION ledger.fixture_reject_cursor()`); e != nil {
		t.Fatal(e)
	}
	if e := gate.With(ctx, "fixture-quarantine", func(ctx context.Context) error {
		if e := s.QuarantineAuth(ctx, r); e != nil {
			return e
		}
		return s.QuarantineAuth(ctx, r)
	}); e != nil {
		t.Fatal(e)
	}
	if cursor, e := s.Cursor(ctx, r.Source); e != nil || cursor != strconv.Itoa(len(raw)) {
		t.Fatal(cursor, e)
	}
	var original []byte
	if e := s.pool.QueryRow(ctx, `SELECT original FROM bootstrap_private.auth_quarantine WHERE source=$1`, r.Source).Scan(&original); e != nil || !bytes.Equal(original, raw) {
		t.Fatal("original malformed bytes changed", e)
	}
	if count(t, s, "work") != 0 {
		t.Fatal("malformed range fabricated business event")
	}
	if _, e := runtimeStore(t, s, c).pool.Exec(ctx, `SELECT original FROM bootstrap_private.auth_quarantine`); e == nil {
		t.Fatal("runtime read protected malformed bytes")
	}
	if e := s.AuthEvent(ctx, r.Source, strconv.Itoa(len(raw)), strconv.Itoa(len(raw)+10), "next-valid", json.RawMessage(`{"event":"Access-Accept"}`)); e != nil {
		t.Fatal(e)
	}
	if proven, e := s.AuthQuarantineRecorded(ctx, r); e != nil || !proven {
		t.Fatal("lost acknowledgement cannot reconcile after later valid event", proven, e)
	}
}
