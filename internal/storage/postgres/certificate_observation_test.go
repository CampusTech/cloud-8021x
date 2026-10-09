package postgres

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/events/auth"
)

func seenCertificate(t *testing.T, id string, at, expires time.Time, ca string) json.RawMessage {
	t.Helper()
	e := auth.Event{Event: "Access-Accept", DeviceID: id, Fingerprint: strings.Repeat("a", 64), Received: at, CertificateObservation: &auth.CertificateObservation{ExpiresAt: expires.Unix(), CAInstance: ca}}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestClientExpiryUsesVerifiedLatestUnexpired48HourWindow(t *testing.T) {
	now := time.Unix(1800000000, 0)
	raw := []json.RawMessage{
		seenCertificate(t, "fleet:owned-acme", now, now.Add(time.Hour), "ec"),
		seenCertificate(t, "fleet:owned-acme", now.Add(-time.Minute), now.Add(72*time.Hour), "ec"),
		seenCertificate(t, "byod:opaque", now, now.Add(2*time.Hour), "wifi"),
		seenCertificate(t, "fleet:windows", now, now.Add(47*time.Hour), "rsa"),
		seenCertificate(t, "fleet:expired", now.Add(-time.Hour), now, "ec"),
		seenCertificate(t, "fleet:edge", now, now.Add(48*time.Hour), "ec"),
		seenCertificate(t, "fleet:other", now, now.Add(time.Hour), "other"),
	}
	count, err := countClientExpiry(raw, now)
	if err != nil || count != 2 {
		t.Fatal("seen ACME/BYOD/Windows renewal/window differs", count, err)
	}
	count, err = countClientExpiry([]json.RawMessage{raw[3]}, now.Add(49*time.Hour))
	if err != nil || count != 0 {
		t.Fatal("expired formerly seen client counted", count, err)
	}
	for name, input := range map[string][]json.RawMessage{"missing": nil, "old event without observation": {json.RawMessage(`{"event":"Access-Accept","device_id":"fleet:old"}`)}, "unbound": {json.RawMessage(strings.Replace(string(raw[0]), strings.Repeat("a", 64), "", 1))}, "invalid CA": {json.RawMessage(strings.Replace(string(raw[0]), `"ec"`, `"guessed"`, 1))}} {
		t.Run(name, func(t *testing.T) {
			if _, err := countClientExpiry(input, now); err == nil {
				t.Fatal("unavailable coverage invented count")
			}
		})
	}
}
func TestPostgresClientExpiryObservation(t *testing.T) {
	s, c := integration(t)
	reset(t, s)
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := s.ObserveClientExpiry(ctx, now); err == nil {
		t.Fatal("empty ledger invented zero")
	}
	raw := seenCertificate(t, "fleet:owned-acme", now, now.Add(time.Hour), "ec")
	if err := s.AuthEvent(ctx, "fixture-native", "", "1", "seen-acme", raw); err != nil {
		t.Fatal(err)
	}
	runtime := runtimeStore(t, s, c)
	n, err := runtime.ObserveClientExpiry(ctx, now)
	if err != nil || n != 1 {
		t.Fatal("seen ACME absent without managed inventory", n, err)
	}
	renewed := seenCertificate(t, "fleet:owned-acme", now.Add(-time.Minute), now.Add(72*time.Hour), "ec")
	if err := s.AuthEvent(ctx, "fixture-native", "1", "2", "renewed-acme", renewed); err != nil {
		t.Fatal(err)
	}
	n, err = runtime.ObserveClientExpiry(ctx, now)
	if err != nil || n != 0 {
		t.Fatal("renewal did not supersede old expiry", n, err)
	}
}
