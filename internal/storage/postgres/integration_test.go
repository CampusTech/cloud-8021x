package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting"
	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/jackc/pgx/v5"
)

var testKey = []byte(strings.Repeat("k", 32))

func roleDSN(t *testing.T, role, password string) string {
	t.Helper()
	u, err := url.Parse(os.Getenv("C8021X_PG_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(role, password)
	return u.String()
}
func roleStore(t *testing.T, c config.Database, role, password string) *Store {
	t.Helper()
	s, err := New(context.Background(), roleDSN(t, role, password), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}
func runtimeStore(t *testing.T, _ *Store, c config.Database) *Store {
	return roleStore(t, c, "app_runtime", "disposable-runtime")
}
func reset(t *testing.T, s *Store) {
	t.Helper()
	_, err := s.pool.Exec(context.Background(), "TRUNCATE ledger.legacy_usage_floor,bootstrap_private.auth_quarantine,ledger.legacy_collection_guards,ledger.intake,ledger.sessions,ledger.observations,ledger.intervals,ledger.work,ledger.attempts,ledger.quarantine,ledger.reconciliations,ledger.auth_cursors,ledger.import_markers RESTART IDENTITY CASCADE")
	if err != nil {
		t.Fatal(err)
	}
}
func testRaw(session, status string) accounting.Raw {
	return accounting.Raw{SourceIP: "192.0.2.1", NASIP: accounting.Attribute{Value: "192.0.2.2", Count: 1}, Station: accounting.Attribute{Value: "aa:bb:cc:dd:ee:ff", Count: 1}, Session: accounting.Attribute{Value: session, Count: 1}, Status: accounting.Attribute{Value: status, Count: 1}, Duration: accounting.Attribute{Value: "10", Count: 1}, Input: accounting.Attribute{Value: "100", Count: 1}, Output: accounting.Attribute{Value: "200", Count: 1}, Received: time.Unix(1800000000, 0), Client: "client", Location: "site", Host: "host", ReplayID: "replay"}
}
func attributeValue(a accounting.Attribute) any {
	if a.Count == 0 {
		return nil
	}
	return a.Value
}
func insertRaw(ctx context.Context, s *Store, r accounting.Raw) error {
	tag, err := s.pool.Exec(ctx, `INSERT INTO ledger.intake(received_at,source_ip,client_id,location_id,host,replay_id,nas_ip,nas_count,station,station_count,session_id,session_count,status,status_count,session_time,session_time_count,input_octets,input_octets_count,output_octets,output_octets_count,input_gigawords,input_gigawords_count,output_gigawords,output_gigawords_count,class,class_count) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)`, r.Received, r.SourceIP, r.Client, r.Location, r.Host, r.ReplayID, attributeValue(r.NASIP), r.NASIP.Count, attributeValue(r.Station), r.Station.Count, attributeValue(r.Session), r.Session.Count, attributeValue(r.Status), r.Status.Count, attributeValue(r.Duration), r.Duration.Count, attributeValue(r.Input), r.Input.Count, attributeValue(r.Output), r.Output.Count, attributeValue(r.InputHigh), r.InputHigh.Count, attributeValue(r.OutputHigh), r.OutputHigh.Count, attributeValue(r.Class), r.Class.Count)
	if err == nil && tag.RowsAffected() != 1 {
		return errors.New("native insert did not affect one row")
	}
	return err
}
func drain(ctx context.Context, s *Store) error {
	for i := 0; i < 200; i++ {
		r, err := s.ProcessOne(ctx, testKey, binding.MaxAge)
		if err != nil {
			return err
		}
		if !r.Processed {
			return nil
		}
	}
	return errors.New("drain exceeded bound")
}
func count(t *testing.T, s *Store, table string) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(context.Background(), "SELECT count(*) FROM ledger."+pgx.Identifier{table}.Sanitize()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
func TestPostgresSessionFirstAndCrossWorkerDedup(t *testing.T) {
	admin, c := integration(t)
	reset(t, admin)
	a := runtimeStore(t, admin, c)
	b := runtimeStore(t, admin, c)
	native := roleStore(t, c, "app_native", "disposable-native")
	ctx := context.Background()
	// Interim deliberately enters the raw queue BEFORE Start, not a pre-normalized queue.
	r := testRaw("shared", "Interim-Update")
	r.Input = accounting.Attribute{Value: "4294967295", Count: 1}
	r.InputHigh = accounting.Attribute{Value: "4294967295", Count: 1}
	for _, item := range []accounting.Raw{r, testRaw("shared", "Start")} {
		if err := insertRaw(ctx, native, item); err != nil {
			t.Fatal(err)
		}
	}
	errs := make(chan error, 2)
	for _, s := range []*Store{a, b} {
		go func() { errs <- drain(ctx, s) }()
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	var up string
	var events int
	if err := admin.pool.QueryRow(ctx, "SELECT upload::text FROM ledger.intervals").Scan(&up); err != nil || up != fmt.Sprint(uint64(math.MaxUint64)) {
		t.Fatal("queued Start not applied first / precision lost", up, err)
	}
	r.Host = "other-server"
	r.ReplayID = "other-delivery"
	r.Received = r.Received.Add(time.Second)
	if err := insertRaw(ctx, native, r); err != nil {
		t.Fatal(err)
	}
	if err := drain(ctx, b); err != nil {
		t.Fatal(err)
	}
	if events = count(t, admin, "observations"); events != 2 || count(t, admin, "intervals") != 1 || count(t, admin, "work") != 3 {
		t.Fatal("semantic retry generated work", events)
	}
	var logged bool
	if err := admin.pool.QueryRow(ctx, "SELECT bool_and(relpersistence='p') FROM pg_class WHERE relnamespace='ledger'::regnamespace AND relkind='r'").Scan(&logged); err != nil || !logged {
		t.Fatal("unlogged state", err)
	}
}
func TestPostgresParallelSessionsAndConcurrentCreation(t *testing.T) {
	admin, c := integration(t)
	reset(t, admin)
	s := runtimeStore(t, admin, c)
	native := roleStore(t, c, "app_native", "disposable-native")
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- insertRaw(ctx, native, testRaw("same", "Start")) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if count(t, admin, "sessions") != 1 || count(t, admin, "intake") != 12 {
		t.Fatal("creation race")
	}
	if err := insertRaw(ctx, native, testRaw("different", "Start")); err != nil {
		t.Fatal(err)
	}
	tx, err := admin.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	k, _ := accounting.CanonicalKey(testRaw("same", "Start"))
	if _, err = tx.Exec(ctx, "SELECT 1 FROM ledger.sessions WHERE session_key=$1 FOR UPDATE", accounting.SessionKey(k)); err != nil {
		t.Fatal(err)
	}
	got, err := s.ProcessOne(ctx, testKey, binding.MaxAge)
	if err != nil || !got.Processed {
		t.Fatal("unrelated session blocked", got, err)
	}
	var key string
	if err = admin.pool.QueryRow(ctx, "SELECT session_key FROM ledger.observations WHERE event_id=$1", got.EventID).Scan(&key); err != nil || key == accounting.SessionKey(k) {
		t.Fatal("wrong locked session", err)
	}
	rollback(tx)
	if err := drain(ctx, s); err != nil {
		t.Fatal(err)
	}
	if count(t, admin, "observations") != 2 {
		t.Fatal("creation retries not deduped")
	}
}
func TestPostgresQuarantineAndUnattributed(t *testing.T) {
	admin, c := integration(t)
	reset(t, admin)
	s := runtimeStore(t, admin, c)
	ctx := context.Background()
	cases := []accounting.Raw{testRaw("ambiguous", "Start"), testRaw("malformed", "Interim-Update"), testRaw("bad-status", "unknown"), testRaw("bad-class", "Start"), testRaw("unattributed", "Start")}
	cases[0].Session.Count = 2
	cases[1].InputHigh = accounting.Attribute{Value: "oops", Count: 1}
	cases[3].Class = accounting.Attribute{Value: "not-signed", Count: 2}
	for _, r := range cases {
		if err := insertRaw(ctx, s, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := drain(ctx, s); err != nil {
		t.Fatal(err)
	}
	if count(t, admin, "quarantine") != 4 || count(t, admin, "observations") != 2 || count(t, admin, "intervals") != 0 || count(t, admin, "sessions") != 4 {
		t.Fatal("invalid input lost or identity invented")
	}
	var attributed bool
	if err := admin.pool.QueryRow(ctx, "SELECT bool_or(event->'Identity'<>'null'::jsonb) FROM ledger.observations").Scan(&attributed); err != nil || attributed {
		t.Fatal("fabricated identity", err)
	}
}
func TestPostgresKilledTransactionRecovery(t *testing.T) {
	admin, c := integration(t)
	reset(t, admin)
	s := runtimeStore(t, admin, c)
	ctx := context.Background()
	for _, status := range []string{"Start", "Interim-Update"} {
		if err := insertRaw(ctx, s, testRaw("crash", status)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.ProcessOne(ctx, testKey, binding.MaxAge); err != nil {
		t.Fatal(err)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	result, err := processLocked(ctx, tx, testKey, binding.MaxAge)
	if err != nil || result.UsageID == "" {
		t.Fatal(result, err)
	}
	pid := tx.Conn().PgConn().PID()
	if _, err = admin.pool.Exec(ctx, "SELECT pg_terminate_backend($1)", pid); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err == nil {
		t.Fatal("killed transaction committed")
	}
	resolved, err := s.ResolveIntake(ctx, result.IntakeID)
	if err != nil || resolved.Processed {
		t.Fatal("crash advanced committed state", err)
	}
	if count(t, admin, "intervals") != 0 || count(t, admin, "work") != 1 {
		t.Fatal("partial commit")
	}
	if err = drain(ctx, s); err != nil {
		t.Fatal(err)
	}
	if count(t, admin, "intervals") != 1 || count(t, admin, "work") != 3 {
		t.Fatal("crash lost interval")
	}
	// Process death after commit: a new pool resolves the committed stable identity.
	s.Close()
	fresh := runtimeStore(t, admin, c)
	resolved, err = fresh.ResolveIntake(ctx, result.IntakeID)
	if err != nil || !resolved.Processed {
		t.Fatal("committed identity not recoverable", err)
	}
}
func TestPostgresAuthCursorAndImportAtomicity(t *testing.T) {
	admin, c := integration(t)
	reset(t, admin)
	s := runtimeStore(t, admin, c)
	ctx := context.Background()
	payload := json.RawMessage(`{"event":"Access-Accept"}`)
	if err := s.AuthEvent(ctx, "host:file", "", "10", "record10", payload); err != nil {
		t.Fatal(err)
	}
	if err := s.AuthEvent(ctx, "host:file", "", "10", "record10", payload); err != nil {
		t.Fatal("replay not idempotent", err)
	}
	if err := s.AuthEvent(ctx, "host:file", "", "20", "record20", payload); !errors.Is(err, ErrCursorConflict) {
		t.Fatal("stale cursor accepted", err)
	}
	if count(t, admin, "work") != 1 {
		t.Fatal("auth duplicate")
	}
	callback := func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO ledger.sessions(session_key,initialized,duration,upload,download,bits,marked,stopped) VALUES('legacy',true,20,18446744073709551615,2,64,false,true)")
		return err
	}
	imported, err := s.ImportOnce(ctx, "legacy-v1", "sum", callback)
	if err != nil || !imported {
		t.Fatal(imported, err)
	}
	imported, err = s.ImportOnce(ctx, "legacy-v1", "sum", callback)
	if err != nil || imported {
		t.Fatal("import replay", err)
	}
	if _, err = s.ImportOnce(ctx, "legacy-v1", "different", callback); err == nil {
		t.Fatal("checksum changed")
	}
	if _, err = s.ImportOnce(ctx, "rollback", "sum", func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO ledger.sessions(session_key)VALUES('must-rollback')"); err != nil {
			return err
		}
		return errors.New("synthetic failure")
	}); err == nil {
		t.Fatal("failed import accepted")
	}
	if count(t, admin, "sessions") != 1 || count(t, admin, "import_markers") != 1 {
		t.Fatal("import partial state")
	}
}

func TestPostgresAuthConflictCannotAdvanceCursor(t *testing.T) {
	admin, c := integration(t)
	reset(t, admin)
	s := runtimeStore(t, admin, c)
	ctx := context.Background()
	if err := s.AuthEvent(ctx, "log", "", "1", "stable", json.RawMessage(`{"event":"A"}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.AuthEvent(ctx, "log", "1", "2", "stable", json.RawMessage(`{"event":"B"}`)); err == nil {
		t.Fatal("changed stable event advanced cursor")
	}
	cursor, err := s.Cursor(ctx, "log")
	if err != nil || cursor != "1" {
		t.Fatal("failed outbox changed cursor", cursor, err)
	}
}

func TestPostgresTransactionDurabilityAndSessionKeyParity(t *testing.T) {
	admin, c := integration(t)
	reset(t, admin)
	c.MaxConnections = 1
	s := runtimeStore(t, admin, c)
	ctx := context.Background()
	if _, err := s.pool.Exec(ctx, "SET synchronous_commit=off"); err != nil {
		t.Fatal(err)
	}
	tx, err := s.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	var sync string
	if err = tx.QueryRow(ctx, "SHOW synchronous_commit").Scan(&sync); err != nil || sync != "on" {
		t.Fatal("transaction durability not forced", sync, err)
	}
	rollback(tx)
	native := roleStore(t, c, "app_native", "disposable-native")
	ntx, err := native.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(ntx)
	if _, err = ntx.Exec(ctx, "SET LOCAL synchronous_commit=off"); err != nil {
		t.Fatal(err)
	}
	if _, err = ntx.Exec(ctx, "INSERT INTO ledger.intake(received_at,source_ip,client_id,location_id,host,replay_id) VALUES(now(),'','','','','')"); err != nil {
		t.Fatal(err)
	}
	if err = ntx.QueryRow(ctx, "SHOW synchronous_commit").Scan(&sync); err != nil || sync != "on" {
		t.Fatal("native acknowledgment durability not forced", sync, err)
	}
	rollback(ntx)
	for _, value := range []string{" session ", "\tunicode-東京\r", strings.Repeat("x", 254)} {
		r := testRaw(value, "Start")
		r.Station.Value = "\taa-bb-cc-dd-ee-ff\n"
		if err = insertRaw(ctx, s, r); err != nil {
			t.Fatal(err)
		}
		var stored *string
		if err = admin.pool.QueryRow(ctx, "SELECT session_key FROM ledger.intake ORDER BY id DESC LIMIT 1").Scan(&stored); err != nil {
			t.Fatal(err)
		}
		key, e := accounting.CanonicalKey(r)
		if e != nil {
			if stored != nil {
				t.Fatal("oversized identity queued")
			}
		} else if stored == nil || *stored != accounting.SessionKey(key) {
			t.Fatal("SQL and Go session keys differ", stored, key)
		}
	}
}

func TestPostgresInvalidNetworkKeysQuarantine(t *testing.T) {
	admin, c := integration(t)
	reset(t, admin)
	s := runtimeStore(t, admin, c)
	ctx := context.Background()
	for _, value := range []string{"unknown", "N/A", "192.0.2.1/24", "127.1", "", "001.2.3.4"} {
		r := testRaw("unknown-network", "Start")
		r.SourceIP = value
		if err := insertRaw(ctx, s, r); err != nil {
			t.Fatal("invalid source blocked native buffering", err)
		}
		r = testRaw("unknown-network", "Start")
		r.NASIP.Value = value
		if err := insertRaw(ctx, s, r); err != nil {
			t.Fatal("invalid NAS blocked native buffering", err)
		}
	}
	if err := drain(ctx, s); err != nil {
		t.Fatal(err)
	}
	if count(t, admin, "sessions") != 0 || count(t, admin, "quarantine") != 12 {
		t.Fatal("invalid network identity created sessions")
	}
}
