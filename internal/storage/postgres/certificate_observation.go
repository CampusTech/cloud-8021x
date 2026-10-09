package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/events/auth"
)

const seenAuthLimit = 50000

var seenFingerprint = regexp.MustCompile(`^[a-f0-9]{64}$`)

// ObserveClientExpiry covers only the last bounded accepted auth population,
// including serial ACME and serial-free clients. It does not inventory issuance.
// Missing/malformed native observation coverage is unavailable, never zero.
func (s *Store) ObserveClientExpiry(ctx context.Context, now time.Time) (int, error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT jsonb_build_object('event',payload->'event','device_id',payload->'device_id','certificate_fingerprint',payload->'certificate_fingerprint','received_at',payload->'received_at','certificate_observation',payload->'certificate_observation') FROM ledger.work WHERE kind='outbox' AND id LIKE 'auth:%' AND payload->>'event'='Access-Accept' ORDER BY created_at DESC,id DESC LIMIT 50000`)
	if err != nil {
		return 0, safeError(err)
	}
	defer rows.Close()
	var raw []json.RawMessage
	size := 0
	for rows.Next() {
		var item []byte
		if rows.Scan(&item) != nil {
			return 0, ErrUnavailable
		}
		size += len(item)
		if len(raw) >= seenAuthLimit || size > 16<<20 {
			return 0, errors.New("seen certificate observation exceeds bound")
		}
		raw = append(raw, item)
	}
	if rows.Err() != nil {
		return 0, ErrUnavailable
	}
	return countClientExpiry(raw, now)
}
func countClientExpiry(raw []json.RawMessage, now time.Time) (int, error) {
	if len(raw) == 0 || len(raw) > seenAuthLimit {
		return 0, errors.New("seen certificate coverage unavailable")
	}
	latest := map[string]int64{}
	for _, data := range raw {
		var e auth.Event
		if json.Unmarshal(data, &e) != nil || e.Event != "Access-Accept" || e.DeviceID == "" || len(e.DeviceID) > 256 || !seenFingerprint.MatchString(e.Fingerprint) || e.Received.IsZero() || e.Received.After(now) || e.CertificateObservation == nil {
			return 0, errors.New("seen certificate coverage unavailable")
		}
		ob := e.CertificateObservation
		if ob.ExpiresAt <= e.Received.Unix() || (ob.CAInstance != "ec" && ob.CAInstance != "rsa" && ob.CAInstance != "wifi" && ob.CAInstance != "other") {
			return 0, errors.New("seen certificate observation invalid")
		}
		if ob.CAInstance == "other" {
			continue
		}
		// A renewed certificate wins even when a delayed old auth event arrives later.
		if ob.ExpiresAt > latest[e.DeviceID] {
			latest[e.DeviceID] = ob.ExpiresAt
		}
	}
	n := 0
	for _, expires := range latest {
		if expires > now.Unix() && expires < now.Add(48*time.Hour).Unix() {
			n++
		}
	}
	return n, nil
}
