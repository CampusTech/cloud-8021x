package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

func TestCertificateCoverageDoesNotImplyVLANReadiness(t *testing.T) {
	now := time.Unix(1700000000, 0)
	fp := strings.Repeat("ab", 32)
	fps := []string{fp}
	devices := []domain.Device{{ID: "other:7", Identities: []string{"byod"}, Groups: []domain.GroupID{"other:4"}, Enrolled: true, Fingerprints: &fps, CertificatesObservedAt: domain.Unix(now)}}
	inventory, err := domain.BuildSnapshot(devices, domain.Unix(now))
	if err != nil {
		t.Fatal(err)
	}
	observation := map[domain.DeviceID]domain.CertificateObservation{"other:7": {DeviceID: "other:7", Fingerprints: fps, ObservedAt: domain.Unix(now), TrustVerified: true, ExpiresAt: map[string]domain.Timestamp{fp: domain.Unix(now.Add(time.Hour))}}}
	cfg := Config{IdentityMode: FingerprintMode, InventoryMaxAge: time.Hour, CertificateMaxAge: 24 * time.Hour, Locations: []Location{{ID: "nyc", VLANEnabled: true}, {ID: "sac", VLANEnabled: false}}}
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	hosts := []ReadinessDevice{{ID: "other:7", Enrolled: true}}
	r := CertificateReadiness(hosts, observation, inventory, e, now.Add(time.Second))
	if r.Ready || r.Devices[0].Reason != "no_vlan_assignment" || r.Devices[0].CertificateReason != "ready" {
		t.Fatal("false readiness", r)
	}
	cfg.Rules = []Rule{{GroupID: "other:4", LocationID: "nyc", VLAN: 200}}
	e, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r = CertificateReadiness(hosts, observation, inventory, e, now.Add(time.Second))
	if !r.Ready || r.ReadyCount != 1 || *r.Devices[0].Locations["nyc"].VLAN != 200 || r.Devices[0].Locations["sac"].VLAN != nil || r.Devices[0].Locations["sac"].DynamicVLANs {
		t.Fatal("readiness locations", r)
	}
	for _, change := range []string{"stale", "untrusted", "expired", "ambiguous", "unenrolled", "empty"} {
		changed := map[domain.DeviceID]domain.CertificateObservation{}
		for k, v := range observation {
			changed[k] = v
		}
		h := append([]ReadinessDevice(nil), hosts...)
		o := changed["other:7"]
		switch change {
		case "stale":
			o.ObservedAt = domain.Unix(now.Add(-24*time.Hour - time.Second))
		case "untrusted":
			o.TrustVerified = false
		case "expired":
			o.ExpiresAt = map[string]domain.Timestamp{fp: domain.Unix(now)}
		case "ambiguous":
			changed["other:8"] = o
		case "unenrolled":
			h[0].Enrolled = false
		case "empty":
			o.Fingerprints = nil
		}
		changed["other:7"] = o
		if CertificateReadiness(h, changed, inventory, e, now.Add(time.Second)).Ready {
			t.Fatal("unsafe readiness", change)
		}
	}
}
