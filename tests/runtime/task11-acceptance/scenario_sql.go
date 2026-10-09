package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting"
	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
	"github.com/jackc/pgx/v5"
)

// This boundary represents fixed SELECT rows, never a substitute product service.
type scenarioSQLRows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close()
}
type scenarioSQLQuery interface {
	Query(context.Context, string, ...any) (scenarioSQLRows, error)
}
type scenarioLedgerBinding struct {
	Deployment, Database, ConfigSHA256 string
	Epoch                              time.Time
}

var scenarioSessionID = regexp.MustCompile(`^task11-[a-z0-9-]{1,57}$`)
var scenarioStation = regexp.MustCompile(`^[0-9a-f]{12}$`)

const scenarioSessionPrefix = "12:10.203.11.4012:10.203.11.4012:"

// LIMIT includes one overflow row. Every iterator is closed before the next query.
func scenarioReadRows(ctx context.Context, q scenarioSQLQuery, sql string, args []any, limit int, visit func(scenarioSQLRows) error) error {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return errors.New("selected SQL rows unavailable")
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		if count > limit {
			return errors.New("selected SQL row bound exceeded")
		}
		if err := visit(rows); err != nil {
			return err
		}
	}
	if rows.Err() != nil {
		return errors.New("selected SQL iterator failed")
	}
	return nil
}
func scenarioSessionKey(encoded string) ([4]string, error) {
	var key [4]string
	raw := encoded
	for i := range key {
		count, rest, ok := strings.Cut(encoded, ":")
		n, err := strconv.Atoi(count)
		if !ok || err != nil || n < 1 || n > 253 || strconv.Itoa(n) != count || len(rest) < n {
			return key, errors.New("canonical selected session key required")
		}
		key[i], encoded = rest[:n], rest[n:]
	}
	if encoded != "" || key[0] != "10.203.11.40" || key[1] != "10.203.11.40" || !scenarioStation.MatchString(key[2]) || !scenarioSessionID.MatchString(key[3]) || accounting.SessionKey(key) != raw {
		return key, errors.New("foreign selected session identity")
	}
	return key, nil
}
func scenarioCounter(raw string) (uint64, error) {
	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || strconv.FormatUint(v, 10) != raw {
		return 0, errors.New("exact unsigned SQL counter required")
	}
	return v, nil
}
func scenarioBudget(budget *int, blobs ...[]byte) error {
	for _, b := range blobs {
		*budget -= len(b)
		if *budget < 0 {
			return errors.New("selected SQL raw byte bound exceeded")
		}
	}
	return nil
}
func scenarioObject(raw []byte) bool {
	var obj map[string]json.RawMessage
	return domain.DecodeJSONStrict(raw, &obj) == nil && obj != nil
}
func scenarioSessionPatterns(sessions []string) ([]string, error) {
	if len(sessions) < 1 || len(sessions) > 8 {
		return nil, errors.New("unique bounded selected session IDs required")
	}
	wanted := map[string]bool{}
	patterns := make([]string, 0, len(sessions))
	for _, id := range sessions {
		if !scenarioSessionID.MatchString(id) || wanted[id] {
			return nil, errors.New("unique bounded selected session IDs required")
		}
		wanted[id] = true
		// Valid IDs contain no LIKE wildcard. Independently parse the station.
		patterns = append(patterns, scenarioSessionPrefix+strings.Repeat("_", 12)+strconv.Itoa(len(id))+":"+id)
	}
	return patterns, nil
}
func readScenarioAccountingRows(ctx context.Context, q scenarioSQLQuery, sessions []string, binding scenarioLedgerBinding) (out scenariocontract.LedgerObservation, err error) {
	if binding.Deployment != "task11-green" || binding.Database != "cloud8021x_task11_green" || !validSHA(binding.ConfigSHA256) || binding.Epoch.IsZero() || len(sessions) < 1 || len(sessions) > 8 {
		return out, errors.New("fixed selected ledger binding required")
	}
	patterns, err := scenarioSessionPatterns(sessions)
	if err != nil {
		return out, err
	}
	wanted := map[string]bool{}
	for _, id := range sessions {
		wanted[id] = true
	}
	out = scenariocontract.LedgerObservation{Deployment: binding.Deployment, Database: binding.Database, Epoch: binding.Epoch.UTC(), ConfigSHA256: binding.ConfigSHA256, ReadOnly: true, Isolation: "repeatable-read"}
	budget := scenariocontract.MaxOpaqueBytes
	keys := map[string]bool{}
	identities := map[string]bool{}
	selectedKeys := []string{}
	err = scenarioReadRows(ctx, q, `SELECT session_key,initialized,duration::text,upload::text,download::text,bits,marked,stopped,last_seen,identity,native_baseline_required,pending FROM ledger.sessions WHERE session_key LIKE ANY($1::text[]) ORDER BY session_key LIMIT 9`, []any{patterns}, 8, func(r scenarioSQLRows) error {
		var s scenariocontract.SessionObservation
		var duration, upload, download string
		var seen *time.Time
		var identity []byte
		if r.Scan(&s.SessionKey, &s.State.Initialized, &duration, &upload, &download, &s.State.Bits, &s.State.Marked, &s.State.Stopped, &seen, &identity, &s.NativeBaselineRequired, &s.Pending) != nil {
			return errors.New("selected session row invalid")
		}
		key, e := scenarioSessionKey(s.SessionKey)
		if e != nil || !wanted[key[3]] || identities[key[3]] || keys[s.SessionKey] || (s.State.Bits != 32 && s.State.Bits != 64) {
			return errors.New("foreign or ambiguous selected session")
		}
		if e = scenarioBudget(&budget, identity); e != nil {
			return e
		}
		if s.State.Duration, e = scenarioCounter(duration); e != nil {
			return e
		}
		if s.State.Upload, e = scenarioCounter(upload); e != nil {
			return e
		}
		if s.State.Download, e = scenarioCounter(download); e != nil {
			return e
		}
		if seen != nil {
			s.State.LastSeen = seen.UTC()
		}
		if len(identity) != 0 && domain.DecodeJSONStrict(identity, &s.State.Identity) != nil {
			return errors.New("selected session attribution invalid")
		}
		identities[key[3]], keys[s.SessionKey] = true, true
		selectedKeys = append(selectedKeys, s.SessionKey)
		out.Sessions = append(out.Sessions, s)
		return nil
	})
	if err != nil || len(selectedKeys) == 0 {
		return out, err
	}
	events := map[string]string{}
	workIDs := []string{}
	err = scenarioReadRows(ctx, q, `SELECT event_id,intake_id,session_key,received_at,duration::text,upload::text,download::text,event,reason FROM ledger.observations WHERE session_key=ANY($1::text[]) ORDER BY session_key,intake_id,event_id LIMIT 129`, []any{selectedKeys}, 128, func(r scenarioSQLRows) error {
		var v scenariocontract.EventObservation
		var duration, upload, download string
		var raw []byte
		if r.Scan(&v.EventID, &v.IntakeID, &v.SessionKey, &v.ReceivedAt, &duration, &upload, &download, &raw, &v.Reason) != nil {
			return errors.New("selected observation row invalid")
		}
		if !keys[v.SessionKey] || !validSHA(v.EventID) || events[v.EventID] != "" || v.IntakeID < 1 || v.ReceivedAt.IsZero() {
			return errors.New("foreign or duplicate selected observation")
		}
		if e := scenarioBudget(&budget, raw); e != nil {
			return e
		}
		if domain.DecodeJSONStrict(raw, &v.Event) != nil || v.Event.ID != v.EventID || accounting.SessionKey(v.Event.Key) != v.SessionKey || !v.Event.Received.Equal(v.ReceivedAt) {
			return errors.New("selected observation payload differs from row")
		}
		d, e := scenarioCounter(duration)
		if e != nil {
			return e
		}
		u, e := scenarioCounter(upload)
		if e != nil {
			return e
		}
		down, e := scenarioCounter(download)
		if e != nil {
			return e
		}
		if v.Event.Duration != d || v.Event.Upload != u || v.Event.Download != down {
			return errors.New("selected observation counters differ from row")
		}
		v.ReceivedAt = v.ReceivedAt.UTC()
		events[v.EventID] = v.SessionKey
		workIDs = append(workIDs, "accounting:"+v.EventID)
		out.Observations = append(out.Observations, v)
		return nil
	})
	if err != nil {
		return out, err
	}
	usages := map[string]bool{}
	err = scenarioReadRows(ctx, q, `SELECT usage_id,event_id,session_key,upload::text,download::text,seconds::text,payload FROM ledger.intervals WHERE session_key=ANY($1::text[]) ORDER BY session_key,usage_id LIMIT 129`, []any{selectedKeys}, 128, func(r scenarioSQLRows) error {
		var v scenariocontract.IntervalObservation
		var upload, download, seconds string
		var raw []byte
		if r.Scan(&v.UsageID, &v.EventID, &v.SessionKey, &upload, &download, &seconds, &raw) != nil {
			return errors.New("selected interval row invalid")
		}
		if !keys[v.SessionKey] || !validSHA(v.UsageID) || usages[v.UsageID] || events[v.EventID] != v.SessionKey {
			return errors.New("foreign or duplicate selected interval")
		}
		if e := scenarioBudget(&budget, raw); e != nil {
			return e
		}
		if domain.DecodeJSONStrict(raw, &v.Interval) != nil || v.Interval.ID != v.UsageID || accounting.SessionKey(v.Interval.Key) != v.SessionKey {
			return errors.New("selected interval payload differs from row")
		}
		u, e := scenarioCounter(upload)
		if e != nil {
			return e
		}
		d, e := scenarioCounter(download)
		if e != nil {
			return e
		}
		s, e := scenarioCounter(seconds)
		if e != nil {
			return e
		}
		if v.Interval.Upload != u || v.Interval.Download != d || v.Interval.Seconds != s {
			return errors.New("selected interval counters differ from row")
		}
		usages[v.UsageID] = true
		workIDs = append(workIDs, "usage:"+v.UsageID)
		out.Intervals = append(out.Intervals, v)
		return nil
	})
	if err != nil || len(workIDs) == 0 {
		return out, err
	}
	wantedWork := map[string]bool{}
	for _, id := range workIDs {
		wantedWork[id] = true
	}
	work := map[string]int{}
	// RecoveryEvidence is the exact reconciliation row at the work's current
	// generation, not an invented column or an operator-recovery JSON aggregate.
	err = scenarioReadRows(ctx, q, `SELECT w.id,w.kind,w.payload,w.created_at,w.state,w.receipt,(SELECT r.evidence FROM ledger.reconciliations r WHERE r.work_id=w.id AND r.generation=w.generation) FROM ledger.work w WHERE w.id=ANY($1::text[]) ORDER BY w.id LIMIT 257`, []any{workIDs}, 256, func(r scenarioSQLRows) error {
		var w scenariocontract.WorkObservation
		if r.Scan(&w.ID, &w.Kind, &w.Payload, &w.CreatedAt, &w.State, &w.Receipt, &w.RecoveryEvidence) != nil {
			return errors.New("selected outbox row invalid")
		}
		if _, exists := work[w.ID]; exists || !wantedWork[w.ID] || w.Kind != "outbox" || w.CreatedAt.IsZero() || !contains([]string{"pending", "leased", "started", "succeeded", "quarantine"}, w.State) {
			return errors.New("foreign or malformed selected outbox")
		}
		if e := scenarioBudget(&budget, w.Payload, w.Receipt, w.RecoveryEvidence); e != nil {
			return e
		}
		if !scenarioObject(w.Payload) {
			return errors.New("selected outbox payload invalid")
		}
		w.Payload, w.Receipt, w.RecoveryEvidence = bytes.Clone(w.Payload), bytes.Clone(w.Receipt), bytes.Clone(w.RecoveryEvidence)
		w.CreatedAt = w.CreatedAt.UTC()
		work[w.ID] = len(out.Outbox)
		out.Outbox = append(out.Outbox, w)
		return nil
	})
	if err != nil || len(out.Outbox) == 0 {
		return out, err
	}
	actualWork := make([]string, 0, len(out.Outbox))
	for _, w := range out.Outbox {
		actualWork = append(actualWork, w.ID)
	}
	err = scenarioReadRows(ctx, q, `SELECT work_id,generation,owner,started_at,finished_at,outcome,receipt FROM ledger.attempts WHERE work_id=ANY($1::text[]) ORDER BY work_id,generation LIMIT 4097`, []any{actualWork}, 4096, func(r scenarioSQLRows) error {
		var id string
		var a scenariocontract.AttemptObservation
		if r.Scan(&id, &a.Generation, &a.Owner, &a.StartedAt, &a.FinishedAt, &a.Outcome, &a.Receipt) != nil {
			return errors.New("selected attempt row invalid")
		}
		i, exists := work[id]
		if !exists || a.Generation < 1 || a.StartedAt.IsZero() || len(out.Outbox[i].Attempts) >= 16 {
			return errors.New("foreign or oversized selected attempt history")
		}
		prior := out.Outbox[i].Attempts
		if len(prior) > 0 && a.Generation <= prior[len(prior)-1].Generation {
			return errors.New("ambiguous selected attempt generation")
		}
		if e := scenarioBudget(&budget, a.Receipt); e != nil {
			return e
		}
		a.StartedAt = a.StartedAt.UTC()
		if a.FinishedAt != nil {
			t := a.FinishedAt.UTC()
			a.FinishedAt = &t
		}
		a.Receipt = bytes.Clone(a.Receipt)
		out.Outbox[i].Attempts = append(out.Outbox[i].Attempts, a)
		return nil
	})
	return out, err
}
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func scenarioPinnedCertificate(raw []byte, pin string) (*x509.Certificate, error) {
	block, rest := pem.Decode(raw)
	if len(raw) > 1<<20 || adoption.Digest(raw) != pin || block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("pinned original CA PEM differs")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA {
		return nil, errors.New("original CA certificate invalid")
	}
	return cert, nil
}
func readScenarioCARows(ctx context.Context, q scenarioSQLQuery, selectionRaw, rootPEM, intermediatePEM []byte) (out scenariocontract.CAObservation, err error) {
	selection, err := scenariocontract.DecodeCASelection(selectionRaw)
	if err != nil {
		return out, err
	}
	root, err := scenarioPinnedCertificate(rootPEM, selection.OriginalRootSHA256)
	if err != nil {
		return out, err
	}
	inter, err := scenarioPinnedCertificate(intermediatePEM, selection.OriginalIntermediateSHA256)
	if err != nil || inter.CheckSignatureFrom(root) != nil {
		return out, errors.New("original CA intermediate chain differs")
	}
	database := "stepca"
	if selection.Authority == "rsa" {
		database = "stepca_rsa"
	}
	out = scenariocontract.CAObservation{Authority: selection.Authority, Database: database, ReadOnly: true, Isolation: "repeatable-read", Serial: selection.Serial, SelectionSHA256: adoption.Digest(selectionRaw), IssuanceResultSHA256: selection.ResultSHA256, LeafDERSHA256: selection.LeafDERSHA256}
	count := 0
	err = scenarioReadRows(ctx, q, `SELECT nkey,nvalue FROM x509_certs WHERE nkey=$1 ORDER BY nkey LIMIT 2`, []any{[]byte(selection.Serial)}, 1, func(r scenarioSQLRows) error {
		var key, der []byte
		if r.Scan(&key, &der) != nil || !bytes.Equal(key, []byte(selection.Serial)) || len(der) > 1<<20 || adoption.Digest(der) != selection.LeafDERSHA256 {
			return errors.New("selected CA certificate row differs")
		}
		leaf, e := x509.ParseCertificate(der)
		if e != nil || leaf.SerialNumber.String() != selection.Serial || leaf.IsCA || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || leaf.CheckSignatureFrom(inter) != nil {
			return errors.New("selected issued leaf identity or chain differs")
		}
		// Stored records may outlive their validity. Verify the preserved chain
		// at the issuance interval, rather than treating later expiry as absence.
		roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
		roots.AddCert(root)
		intermediates.AddCert(inter)
		if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: leaf.NotBefore.Add(time.Second), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
			return errors.New("selected issued chain invalid")
		}
		count++
		out.CertificateKey, out.CertificateDER = bytes.Clone(key), bytes.Clone(der)
		return nil
	})
	if err != nil {
		return out, err
	}
	if count != 1 {
		return out, errors.New("selected issued certificate missing")
	}
	err = scenarioReadRows(ctx, q, `SELECT nkey,nvalue FROM x509_certs_data WHERE nkey=$1 ORDER BY nkey LIMIT 2`, []any{[]byte(selection.Serial)}, 1, func(r scenarioSQLRows) error {
		var key, raw []byte
		if r.Scan(&key, &raw) != nil || !bytes.Equal(key, out.CertificateKey) || len(raw) > 1<<20 {
			return errors.New("selected CA metadata row differs")
		}
		var data struct {
			Provisioner *struct {
				ID   string `json:"id"`
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"provisioner"`
		}
		name, kind, id := "wifi-acme", "ACME", "acme/wifi-acme"
		if selection.Authority == "rsa" {
			name, kind, id = "wifi-scep", "SCEP", "scep/wifi-scep"
		}
		if domain.DecodeJSONStrict(raw, &data) != nil || data.Provisioner == nil || data.Provisioner.ID != id || data.Provisioner.Name != name || data.Provisioner.Type != kind {
			return errors.New("selected original provisioner metadata differs")
		}
		out.CertificateDataPresent = true
		out.CertificateDataKey, out.CertificateData = bytes.Clone(key), bytes.Clone(raw)
		return nil
	})
	if err == nil && selection.Authority == "rsa" && !out.CertificateDataPresent {
		err = errors.New("selected RSA provisioner row missing")
	}
	return out, err
}
func scenarioSQLCredential(raw []byte, cfg config.Database, user, database string) (*pgx.ConnConfig, error) {
	text := strings.TrimSpace(string(raw))
	u, err := url.Parse(text)
	if len(raw) == 0 || len(raw) > 64<<10 || err != nil || u.Scheme != "postgresql" || u.Hostname() != "10.203.11.11" || (u.Port() != "" && u.Port() != "5432") || u.Path != "/"+database || u.User == nil || u.User.Username() != user || u.Fragment != "" || u.Opaque != "" || cfg.Name != database {
		return nil, errors.New("fixed private SQL credential identity differs")
	}
	password, present := u.User.Password()
	if !present || password == "" || strings.ContainsAny(password, "\r\n\x00") {
		return nil, errors.New("protected SQL password invalid")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil || query.Get("sslmode") != "verify-full" {
		return nil, errors.New("protected SQL TLS mode differs")
	}
	for key, values := range query {
		if len(values) != 1 || (key != "sslmode" && key != "sslrootcert") || (key == "sslrootcert" && values[0] != "/etc/cloud-8021x/postgres-ca.pem") {
			return nil, errors.New("unapproved private SQL option")
		}
	}
	cc, err := pgx.ParseConfig(text)
	if err != nil || cc.Host != "10.203.11.11" || cc.Port != 5432 || cc.User != user || cc.Database != database {
		return nil, errors.New("protected SQL credential invalid")
	}
	cc.Fallbacks = nil
	cc.ConnectTimeout = 5 * time.Second
	cc.RuntimeParams = map[string]string{"application_name": "task11-read-only-scenario", "statement_timeout": "5000", "lock_timeout": "5000", "idle_in_transaction_session_timeout": "10000"}
	return cc, nil
}
