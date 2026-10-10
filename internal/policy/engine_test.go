package policy

import (
	"context"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/identity"
)

func fixture(t *testing.T) (*Engine, domain.Snapshot, identity.VerifiedCertificate, domain.TrustedNetworkContext, time.Time) {
	t.Helper()
	now := time.Now()
	h := identity.Handoff{Directory: filepath.Join(t.TempDir(), "handoff"), MaxAge: 120 * time.Second}
	leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("verified leaf")})
	path := filepath.Join(t.TempDir(), "leaf")
	_ = os.WriteFile(path, leaf, 0600)
	token := strings.Repeat("a", 64)
	if err := h.Record(path, token, nil, now); err != nil {
		t.Fatal(err)
	}
	// Receipt follows the completed filesystem write, including slow race builds.
	now = time.Now()
	cert, err := h.Consume(token, now.Add(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	fps := []string{cert.Fingerprint()}
	d := domain.Device{ID: "fake:1", HardwareSerial: "SERIAL", Identities: []string{"SERIAL"}, Groups: []domain.GroupID{"fake:staff"}, Enrolled: true, Fingerprints: &fps, CertificatesObservedAt: domain.Unix(now.Add(-time.Second))}
	s, err := domain.BuildSnapshot([]domain.Device{d}, domain.Unix(now))
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(Config{IdentityMode: FingerprintMode, InventoryMaxAge: time.Hour, CertificateMaxAge: time.Hour, Locations: []Location{{ID: "nyc", VLANEnabled: true}, {ID: "sac", VLANEnabled: false}}, Rules: []Rule{{GroupID: "fake:staff", LocationID: "nyc", VLAN: 120}}, FallbackVLAN: 999})
	if err != nil {
		t.Fatal(err)
	}
	return e, s, cert, domain.TrustedNetworkContext{ClientID: "ap", LocationID: "nyc", Medium: domain.WiFi, SignalingProfile: "fake-numeric"}, now.Add(time.Millisecond)
}
func TestExactAuthorizationPolicyAndOptOut(t *testing.T) {
	e, s, cert, ctx, now := fixture(t)
	d, err := e.Authorize(context.Background(), s, cert, ctx, now)
	if err != nil || d.DeviceID != "fake:1" || d.VLAN == nil || d.VLAN.ID != 120 {
		t.Fatalf("decision %+v %v", d, err)
	}
	ctx.LocationID = "sac"
	d, err = e.Authorize(context.Background(), s, cert, ctx, now)
	if err != nil || d.VLAN != nil {
		t.Fatal("optout", err)
	}
	ctx.LocationID = "nyc"
	ctx.Medium = domain.Wired
	d, err = e.Authorize(context.Background(), s, cert, ctx, now)
	if err != nil || d.VLAN != nil {
		t.Fatal("wired", err)
	}
	ctx.LocationID = "unknown"
	if _, err = e.Authorize(context.Background(), s, cert, ctx, now); err == nil {
		t.Fatal("unknown site")
	}
}
func TestCertificateFreshnessAmbiguityEnrollmentAndGroupConflicts(t *testing.T) {
	e, s, cert, ctx, now := fixture(t)
	fp := cert.Fingerprint()
	for _, mutate := range []func(*domain.Snapshot){func(s *domain.Snapshot) { s.Version = 1 }, func(s *domain.Snapshot) { s.UpdatedAt = domain.Unix(now.Add(-time.Hour)) }, func(s *domain.Snapshot) { s.UpdatedAt = domain.Unix(now.Add(time.Second)) }, func(s *domain.Snapshot) { s.Certificates[fp] = nil }, func(s *domain.Snapshot) { s.Certificates[fp].Enrolled = false }, func(s *domain.Snapshot) { v := domain.Unix(now.Add(-time.Hour)); s.Certificates[fp].ObservedAt = &v }, func(s *domain.Snapshot) { s.Certificates[fp].ObservedAt = nil }} {
		changed := s.Clone()
		mutate(&changed)
		if _, err := e.Authorize(context.Background(), changed, cert, ctx, now); err == nil {
			t.Fatal("invalid cert authorized")
		}
	}
	if _, err := e.Authorize(context.Background(), s, identity.VerifiedCertificate{}, ctx, now); err == nil {
		t.Fatal("unverified zero cert")
	}
	cfg := e.Config()
	cfg.Rules = append(cfg.Rules, Rule{GroupID: "fake:other", LocationID: "nyc", VLAN: 121})
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.Certificates[fp].Groups = append(s.Certificates[fp].Groups, "fake:other")
	if _, err = e.Authorize(context.Background(), s, cert, ctx, now); err == nil {
		t.Fatal("group conflict")
	}
	s.Certificates[fp].Groups = []domain.GroupID{"unmatched"}
	d, err := e.Authorize(context.Background(), s, cert, ctx, now)
	if err != nil || d.VLAN.ID != 999 {
		t.Fatal("fallback", err)
	}
}
func TestLegacyModeCurrentInventoryAndNoNeutralCNFallback(t *testing.T) {
	e, s, cert, ctx, now := fixture(t)
	if _, err := e.AuthorizeLegacy(context.Background(), s, "SERIAL", ctx, now); err == nil {
		t.Fatal("CN bypass")
	}
	cfg := e.Config()
	cfg.IdentityMode = LegacySerialMode
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.AuthorizeLegacy(context.Background(), s, " SERIAL Campus WiFi ", ctx, now); err != nil {
		t.Fatal(err)
	}
	s.Identities["cloud-8021x-inventory"] = s.Identities["SERIAL"]
	if _, err := e.AuthorizeLegacy(context.Background(), s, "cloud-8021x-inventory", ctx, now); err == nil {
		t.Fatal("neutral subject fallback")
	}
	s.Identities["SERIAL"].Enrolled = false
	if _, err := e.AuthorizeLegacy(context.Background(), s, "SERIAL", ctx, now); err == nil {
		t.Fatal("stale enrollment")
	}
	if _, err := e.Authorize(context.Background(), s, cert, ctx, now); err == nil {
		t.Fatal("mode mixed")
	}
}
func TestTrustedSourceMapRejectsPacketSelectedContexts(t *testing.T) {
	m, err := NewTrustMap([]Client{{ID: "nyc-client", LocationID: "nyc", CIDRs: []string{"192.0.2.0/24"}, Medium: domain.WiFi, SignalingProfile: "unifi-numeric"}, {ID: "sac-client", LocationID: "sac", CIDRs: []string{"198.51.100.1/32"}, Medium: domain.Wired}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := m.AuthenticatedClient("nyc-client", "192.0.2.17")
	if err != nil || c.LocationID != "nyc" || c.SignalingProfile != "unifi-numeric" {
		t.Fatal(c, err)
	}
	for _, tc := range [][2]string{{"sac-client", "192.0.2.17"}, {"unknown", "192.0.2.17"}, {"nyc-client", "192.0.3.1"}, {"nyc-client", "spoof"}, {"nyc-client", "::ffff:192.0.2.17"}} {
		if _, err := m.AuthenticatedClient(tc[0], tc[1]); err == nil {
			t.Fatal("source bypass", tc)
		}
	}
	for _, cidrs := range [][]string{{"192.0.2.1/24"}, {"0.0.0.0/0"}, {"192.0.2.0/24", "192.0.2.1/32"}} {
		if _, err := NewTrustMap([]Client{{ID: "a", LocationID: "nyc", CIDRs: cidrs, Medium: domain.WiFi}}); err == nil {
			t.Fatal("bad CIDR")
		}
	}
}
func TestAttestedHardwareAuthorizationIsIndependentOfCertificatePolling(t *testing.T) {
	e, s, plain, network, now := fixture(t)
	cfg := e.Config()
	cfg.AttestedACME = true
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "handoff")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("b", 64)
	body := `{"fingerprint":"` + plain.Fingerprint() + `","attested_serial":"SERIAL"}`
	if err := os.WriteFile(filepath.Join(dir, token), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cert, err := (identity.Handoff{Directory: dir, MaxAge: 120 * time.Second}).Consume(token, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s.Certificates = map[string]*domain.DeviceRecord{}
	d, err := e.Authorize(context.Background(), s, cert, network, now)
	if err != nil || d.DeviceID != "fake:1" || d.VLAN.ID != 120 {
		t.Fatal("hardware route", err)
	}
	cfg.AttestedACME = false
	disabled, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := disabled.Authorize(context.Background(), s, cert, network, now); err == nil {
		t.Fatal("disabled attestation")
	}
	s.HardwareSerials["SERIAL"] = nil
	if _, err := e.Authorize(context.Background(), s, cert, network, now); err == nil {
		t.Fatal("ambiguous serial or alias fallback")
	}
}
