package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting"
	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

// Synthetic row values test the reader codec and query association only. They
// are never signed receipts or assertions about an installed product/database.
type scenarioTestRows struct {
	values [][]any
	next   int
	closed bool
	rowErr error
}

func (r *scenarioTestRows) Next() bool { r.next++; return r.next <= len(r.values) }
func (r *scenarioTestRows) Scan(dst ...any) error {
	values := r.values[r.next-1]
	if len(dst) != len(values) {
		return errors.New("test row column mismatch")
	}
	for i, v := range values {
		d := reflect.ValueOf(dst[i]).Elem()
		if v == nil {
			d.SetZero()
		} else {
			value := reflect.ValueOf(v)
			if !value.Type().AssignableTo(d.Type()) {
				return errors.New("test row type mismatch")
			}
			d.Set(value)
		}
	}
	return nil
}
func (r *scenarioTestRows) Err() error { return r.rowErr }
func (r *scenarioTestRows) Close()     { r.closed = true }

type scenarioTestQuery struct {
	t     *testing.T
	rows  map[string]*scenarioTestRows
	calls []string
	args  map[string][]any
	err   error
}

func (q *scenarioTestQuery) Query(_ context.Context, sql string, args ...any) (scenarioSQLRows, error) {
	if q.err != nil {
		return nil, q.err
	}
	for _, table := range []string{"ledger.sessions", "ledger.observations", "ledger.intervals", "ledger.work", "ledger.attempts", "x509_certs_data", "x509_certs"} {
		if strings.Contains(sql, "FROM "+table+" ") || strings.Contains(sql, "FROM "+table+"\n") {
			if !strings.HasPrefix(sql, "SELECT ") || !strings.Contains(sql, "$1") || !strings.Contains(sql, "LIMIT ") {
				q.t.Fatal("reader used an unbounded or unparameterized query", sql)
			}
			q.calls = append(q.calls, table)
			q.args[table] = args
			r := q.rows[table]
			if r == nil {
				q.t.Fatal("unexpected row source", table)
			}
			return r, nil
		}
	}
	q.t.Fatal("unexpected SQL statement", sql)
	return nil, errors.New("unexpected query")
}
func scenarioLedgerRows(t *testing.T) (*scenarioTestQuery, scenarioLedgerBinding, []string) {
	t.Helper()
	at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	key := [4]string{"10.203.11.40", "10.203.11.40", "aabbccddeeff", "task11-read-a"}
	sessionKey := accounting.SessionKey(key)
	eventID, usageID := strings.Repeat("a", 64), strings.Repeat("b", 64)
	event := accounting.Event{ID: eventID, Key: key, Duration: 60, Upload: math.MaxUint64, Download: 9007199254740993, Bits: 64, Marked: true, Received: at, Status: "Interim-Update"}
	interval := accounting.Interval{ID: usageID, Key: key, Upload: 7, Download: 9, Seconds: 3, Received: at, Bits: 64}
	eventRaw, _ := json.Marshal(event)
	intervalRaw, _ := json.Marshal(interval)
	payload := []byte(`{ "event_id": "` + eventID + `", "wide": 18446744073709551615, "escaped": "<\u0026>" }`)
	receipt := []byte(`{ "outcome": "succeeded", "synthetic_codec_only": true }`)
	recovery := []byte(`{ "synthetic_codec_only": true, "wide": 9007199254740993 }`)
	q := &scenarioTestQuery{t: t, args: map[string][]any{}, rows: map[string]*scenarioTestRows{
		"ledger.sessions":     {values: [][]any{{sessionKey, true, "60", "18446744073709551615", "9007199254740993", 64, true, false, &at, []byte("null"), false, false}}},
		"ledger.observations": {values: [][]any{{eventID, int64(17), sessionKey, at, "60", "18446744073709551615", "9007199254740993", eventRaw, "interval"}}},
		"ledger.intervals":    {values: [][]any{{usageID, eventID, sessionKey, "7", "9", "3", intervalRaw}}},
		"ledger.work":         {values: [][]any{{"accounting:" + eventID, "outbox", payload, at, "succeeded", receipt, recovery}}},
		"ledger.attempts":     {values: [][]any{{"accounting:" + eventID, int64(1), "synthetic-worker", at, &at, stringPtr("succeeded"), receipt}}},
	}}
	return q, scenarioLedgerBinding{"task11-green", "cloud8021x_task11_green", strings.Repeat("c", 64), at.Add(-time.Hour)}, []string{"task11-read-a"}
}
func stringPtr(v string) *string { return &v }
func TestScenarioAccountingReadsSelectedExactRows(t *testing.T) {
	q, binding, sessions := scenarioLedgerRows(t)
	got, err := readScenarioAccountingRows(context.Background(), q, sessions, binding)
	if err != nil {
		t.Fatal(err)
	}
	if got.Database != binding.Database || got.Deployment != binding.Deployment || got.ConfigSHA256 != binding.ConfigSHA256 || !got.Epoch.Equal(binding.Epoch) || !got.ReadOnly || got.Isolation != "repeatable-read" {
		t.Fatal("actual snapshot association lost")
	}
	if len(got.Sessions) != 1 || got.Sessions[0].State.Upload != math.MaxUint64 || got.Sessions[0].State.Download != 9007199254740993 || len(got.Observations) != 1 || got.Observations[0].Event.Upload != math.MaxUint64 || len(got.Intervals) != 1 || got.Intervals[0].Interval.Seconds != 3 || len(got.Outbox) != 1 || len(got.Outbox[0].Attempts) != 1 {
		t.Fatal("typed rows lost exact integer/association values")
	}
	w := got.Outbox[0]
	if !bytes.Equal(w.Payload, q.rows["ledger.work"].values[0][2].([]byte)) || !bytes.Equal(w.Receipt, q.rows["ledger.work"].values[0][5].([]byte)) || !bytes.Equal(w.RecoveryEvidence, q.rows["ledger.work"].values[0][6].([]byte)) || !bytes.Equal(w.Attempts[0].Receipt, q.rows["ledger.attempts"].values[0][6].([]byte)) {
		t.Fatal("stored opaque bytes reconstructed")
	}
	if !reflect.DeepEqual(q.calls, []string{"ledger.sessions", "ledger.observations", "ledger.intervals", "ledger.work", "ledger.attempts"}) {
		t.Fatal("unexpected query topology", q.calls)
	}
	for _, table := range q.calls {
		if !q.rows[table].closed {
			t.Fatal("row reader not closed", table)
		}
	}
	if !reflect.DeepEqual(q.args["ledger.observations"], []any{[]string{got.Sessions[0].SessionKey}}) || !reflect.DeepEqual(q.args["ledger.work"], []any{[]string{"accounting:" + got.Observations[0].EventID, "usage:" + got.Intervals[0].UsageID}}) {
		t.Fatal("selected row relationships not parameterized")
	}
}
func TestScenarioAccountingReportsHonestMissingSession(t *testing.T) {
	q, b, s := scenarioLedgerRows(t)
	q.rows["ledger.sessions"].values = nil
	got, err := readScenarioAccountingRows(context.Background(), q, s, b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Database != b.Database || !got.ReadOnly || len(got.Sessions) != 0 || len(got.Observations) != 0 || len(got.Intervals) != 0 || len(got.Outbox) != 0 || !reflect.DeepEqual(q.calls, []string{"ledger.sessions"}) || !q.rows["ledger.sessions"].closed {
		t.Fatal("missing selected session was fabricated or unrelated rows read")
	}
}
func TestScenarioAccountingRejectsForeignMalformedAndOverflow(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*scenarioTestQuery, *[]string)
	}{
		{"invalid-selector", func(_ *scenarioTestQuery, s *[]string) { *s = []string{"task11-read-a' OR true"} }},
		{"duplicate-selector", func(_ *scenarioTestQuery, s *[]string) { *s = append(*s, (*s)[0]) }},
		{"foreign-session", func(q *scenarioTestQuery, _ *[]string) {
			q.rows["ledger.sessions"].values[0][0] = accounting.SessionKey([4]string{"10.203.11.99", "10.203.11.40", "aabbccddeeff", "task11-read-a"})
		}},
		{"extra-station", func(q *scenarioTestQuery, _ *[]string) {
			row := append([]any(nil), q.rows["ledger.sessions"].values[0]...)
			row[0] = accounting.SessionKey([4]string{"10.203.11.40", "10.203.11.40", "112233445566", "task11-read-a"})
			q.rows["ledger.sessions"].values = append(q.rows["ledger.sessions"].values, row)
		}},
		{"uint64-overflow", func(q *scenarioTestQuery, _ *[]string) {
			q.rows["ledger.sessions"].values[0][3] = "18446744073709551616"
		}},
		{"fractional-counter", func(q *scenarioTestQuery, _ *[]string) { q.rows["ledger.sessions"].values[0][3] = "1.5" }},
		{"event-column-mismatch", func(q *scenarioTestQuery, _ *[]string) { q.rows["ledger.observations"].values[0][5] = "12" }},
		{"unknown-event", func(q *scenarioTestQuery, _ *[]string) {
			q.rows["ledger.intervals"].values[0][1] = strings.Repeat("f", 64)
		}},
		{"foreign-work", func(q *scenarioTestQuery, _ *[]string) {
			q.rows["ledger.work"].values[0][0] = "accounting:" + strings.Repeat("f", 64)
		}},
		{"observation-overflow", func(q *scenarioTestQuery, _ *[]string) {
			row := q.rows["ledger.observations"].values[0]
			q.rows["ledger.observations"].values = make([][]any, 129)
			for i := range q.rows["ledger.observations"].values {
				copyRow := append([]any(nil), row...)
				var event accounting.Event
				_ = json.Unmarshal(copyRow[7].([]byte), &event)
				event.ID = adoption.Digest([]byte(strconv.Itoa(i)))
				copyRow[0] = event.ID
				copyRow[7], _ = json.Marshal(event)
				q.rows["ledger.observations"].values[i] = copyRow
			}
		}},
		{"opaque-overflow", func(q *scenarioTestQuery, _ *[]string) {
			q.rows["ledger.work"].values[0][2] = []byte(`{"x":"` + strings.Repeat("a", scenariocontract.MaxOpaqueBytes) + `"}`)
		}},
		{"row-error", func(q *scenarioTestQuery, _ *[]string) {
			q.rows["ledger.observations"].rowErr = errors.New("synthetic private row error")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q, b, s := scenarioLedgerRows(t)
			q.t = t
			tc.change(q, &s)
			if _, err := readScenarioAccountingRows(context.Background(), q, s, b); err == nil {
				t.Fatal("invalid or truncated observation accepted")
			}
		})
	}
}
func scenarioCAFixture(t *testing.T, authority string) (*scenarioTestQuery, scenariocontract.CASelection, []byte, []byte) {
	t.Helper()
	at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	makeCert := func(serial int64, ca bool, parent *x509.Certificate) (*x509.Certificate, []byte) {
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "synthetic-codec-" + strconv.FormatInt(serial, 10)}, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour), BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature}
		if ca {
			template.KeyUsage |= x509.KeyUsageCertSign
		} else {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		if parent == nil {
			parent = template
		}
		der, e := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, key)
		if e != nil {
			t.Fatal(e)
		}
		cert, e := x509.ParseCertificate(der)
		if e != nil {
			t.Fatal(e)
		}
		return cert, der
	}
	root, rootDER := makeCert(1, true, nil)
	inter, interDER := makeCert(2, true, root)
	_, leaf := makeCert(1234, false, inter)
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	interPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER})
	selection := scenariocontract.CASelection{Schema: 1, AttemptID: "task11-" + strings.Repeat("a", 32), IssuanceSequence: 1, ResultSHA256: strings.Repeat("b", 64), Authority: authority, Serial: "1234", LeafDERSHA256: adoption.Digest(leaf), OriginalRootSHA256: adoption.Digest(rootPEM), OriginalIntermediateSHA256: adoption.Digest(interPEM)}
	metadata := [][]any(nil)
	if authority == "rsa" {
		metadata = [][]any{{[]byte("1234"), []byte(`{ "provisioner": { "id": "scep/wifi-scep", "name": "wifi-scep", "type": "SCEP" } }`)}}
	}
	return &scenarioTestQuery{t: t, args: map[string][]any{}, rows: map[string]*scenarioTestRows{"x509_certs": {values: [][]any{{[]byte("1234"), leaf}}}, "x509_certs_data": {values: metadata}}}, selection, rootPEM, interPEM
}
func TestScenarioCAReadsDERAndHonestMetadataBytes(t *testing.T) {
	for _, authority := range []string{"ec", "rsa"} {
		t.Run(authority, func(t *testing.T) {
			q, s, root, inter := scenarioCAFixture(t, authority)
			raw, _ := json.Marshal(s)
			raw = append([]byte(" \n"), raw...)
			got, err := readScenarioCARows(context.Background(), q, raw, root, inter)
			if err != nil {
				t.Fatal(err)
			}
			database := "stepca"
			if authority == "rsa" {
				database = "stepca_rsa"
			}
			if got.Authority != authority || got.Database != database || got.Serial != s.Serial || got.SelectionSHA256 != adoption.Digest(raw) || got.IssuanceResultSHA256 != s.ResultSHA256 || got.LeafDERSHA256 != s.LeafDERSHA256 || !got.ReadOnly || got.Isolation != "repeatable-read" || !bytes.Equal(got.CertificateKey, []byte(s.Serial)) || !bytes.Equal(got.CertificateDER, q.rows["x509_certs"].values[0][1].([]byte)) {
				t.Fatal("CA row identity lost")
			}
			if got.CertificateDataPresent != (authority == "rsa") {
				t.Fatal("metadata absence fabricated")
			}
			if authority == "rsa" && !bytes.Equal(got.CertificateData, q.rows["x509_certs_data"].values[0][1].([]byte)) {
				t.Fatal("metadata bytes reconstructed")
			}
			for _, table := range q.calls {
				if !q.rows[table].closed || !reflect.DeepEqual(q.args[table], []any{[]byte(s.Serial)}) {
					t.Fatal("unclosed/unbound CA row", table)
				}
			}
		})
	}
}
func TestScenarioCARejectsWrongMissingAndOverflowRows(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*scenarioTestQuery, *scenariocontract.CASelection, *[]byte)
	}{
		{"missing-cert", func(q *scenarioTestQuery, _ *scenariocontract.CASelection, _ *[]byte) {
			q.rows["x509_certs"].values = nil
		}},
		{"duplicate-cert", func(q *scenarioTestQuery, _ *scenariocontract.CASelection, _ *[]byte) {
			q.rows["x509_certs"].values = append(q.rows["x509_certs"].values, q.rows["x509_certs"].values[0])
		}},
		{"wrong-key", func(q *scenarioTestQuery, _ *scenariocontract.CASelection, _ *[]byte) {
			q.rows["x509_certs"].values[0][0] = []byte("other")
		}},
		{"wrong-der-hash", func(_ *scenarioTestQuery, s *scenariocontract.CASelection, _ *[]byte) {
			s.LeafDERSHA256 = strings.Repeat("f", 64)
		}},
		{"wrong-root-pin", func(_ *scenarioTestQuery, _ *scenariocontract.CASelection, root *[]byte) { *root = append(*root, '\n') }},
		{"missing-rsa-data", func(q *scenarioTestQuery, _ *scenariocontract.CASelection, _ *[]byte) {
			q.rows["x509_certs_data"].values = nil
		}},
		{"wrong-provisioner", func(q *scenarioTestQuery, _ *scenariocontract.CASelection, _ *[]byte) {
			q.rows["x509_certs_data"].values[0][1] = []byte(`{"provisioner":{"id":"scep/other","name":"other","type":"SCEP"}}`)
		}},
		{"metadata-key", func(q *scenarioTestQuery, _ *scenariocontract.CASelection, _ *[]byte) {
			q.rows["x509_certs_data"].values[0][0] = []byte("other")
		}},
		{"duplicate-metadata", func(q *scenarioTestQuery, _ *scenariocontract.CASelection, _ *[]byte) {
			q.rows["x509_certs_data"].values = append(q.rows["x509_certs_data"].values, q.rows["x509_certs_data"].values[0])
		}},
		{"metadata-overflow", func(q *scenarioTestQuery, _ *scenariocontract.CASelection, _ *[]byte) {
			q.rows["x509_certs_data"].values[0][1] = bytes.Repeat([]byte(" "), (1<<20)+1)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q, s, root, inter := scenarioCAFixture(t, "rsa")
			tc.change(q, &s, &root)
			raw, _ := json.Marshal(s)
			if _, err := readScenarioCARows(context.Background(), q, raw, root, inter); err == nil {
				t.Fatal("invalid CA evidence accepted")
			}
		})
	}
}
func TestScenarioSQLCredentialsAreClosedAndErrorsDoNotExposeDSN(t *testing.T) {
	cfg := config.Database{Name: "cloud8021x_task11_green"}
	dsn := "postgresql://cloud8021x_task11_green_migrate:synthetic-private@10.203.11.11:5432/cloud8021x_task11_green?sslmode=verify-full"
	cc, err := scenarioSQLCredential([]byte(dsn), cfg, "cloud8021x_task11_green_migrate", cfg.Name)
	if err != nil || cc == nil || cc.Host != "10.203.11.11" || cc.Port != 5432 {
		t.Fatal("valid private identity refused", err)
	}
	for _, bad := range []string{strings.Replace(dsn, "10.203.11.11", "10.203.11.99", 1), strings.Replace(dsn, ":5432/", ":9999/", 1), strings.Replace(dsn, "_migrate:", "_runtime:", 1), strings.Replace(dsn, "/cloud8021x_task11_green?", "/cloud8021x_task11_blue?", 1), dsn + "&host=10.203.11.99", dsn + "&search_path=public", strings.Replace(dsn, "verify-full", "disable", 1)} {
		_, err := scenarioSQLCredential([]byte(bad), cfg, "cloud8021x_task11_green_migrate", cfg.Name)
		if err == nil || strings.Contains(err.Error(), "synthetic-private") || strings.Contains(err.Error(), "postgresql://") {
			t.Fatal("unclosed SQL identity or private error")
		}
	}
}

func TestScenarioSQLShippingModeExposesExistingObserverGap(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "shipping-config.yaml")
	if err := os.WriteFile(path, []byte("synthetic-config-codec-only"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivate(path, 1<<20, os.Getuid()); err == nil {
		t.Fatal("old observer's0600-only read unexpectedly accepted shipping0644 configuration")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readPrivate(path, 1<<20, os.Getuid())
	if err != nil || string(got) != "synthetic-config-codec-only" {
		t.Fatal("mode regression failed to isolate the old0600 assumption", err)
	}
}

func TestScenarioSQLReaderEntryRefusesInvalidInput(t *testing.T) {
	// Invalid input must stop before any guest lock, SQL or socket. Unsupported
	// hosts refuse too. These calls never use installed-state fixtures.
	if _, err := observeScenarioAccounting(context.Background(), nil); err == nil {
		t.Fatal("missing selector reached accounting reader")
	}
	if _, err := observeScenarioCA(context.Background(), []byte(`{}`)); err == nil {
		t.Fatal("missing private selection reached CA reader")
	}
}
