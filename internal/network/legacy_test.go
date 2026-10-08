package network

import (
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

func TestLegacyVLANFallbackKeepsOriginalAgeAndScope(t *testing.T) {
	now := time.Now()
	s := new(Store)
	if e := s.SetLegacyVLANs([]LegacyVLAN{{ProviderID: "p", SiteID: "site", ObservedAt: domain.Unix(now.Add(-time.Minute)), Names: map[int]string{120: "Historical staff"}, Provenance: "legacy-config-bound"}}); e != nil {
		t.Fatal(e)
	}
	if got := s.Resolve("p", "site", "", 120, now, 2*time.Minute); got.VLAN != "Historical staff" || got.Provenance != "legacy-config-bound" || got.Site != "" {
		t.Fatal(got)
	}
	if s.Resolve("p", "other", "", 120, now, 2*time.Minute).VLAN != "" || s.Resolve("p", "site", "", 120, now.Add(time.Minute), 2*time.Minute).VLAN != "" {
		t.Fatal("legacy scope/age promoted")
	}
}

func TestLegacyFallbackCannotExtendOriginalOneHourTTL(t *testing.T) {
	now := time.Now()
	s := new(Store)
	if e := s.SetLegacyVLANs([]LegacyVLAN{{ProviderID: "p", SiteID: "site", ObservedAt: domain.Unix(now.Add(-2 * time.Hour)), Names: map[int]string{120: "Old staff"}, Provenance: "legacy-config-bound"}}); e != nil {
		t.Fatal(e)
	}
	if s.Resolve("p", "site", "", 120, now, 24*time.Hour).VLAN != "" {
		t.Fatal("incoming retention extended original legacy TTL")
	}
}

func TestAuthenticatedVLANGenerationSuppressesLegacyFallback(t *testing.T) {
	now := time.Now()
	for _, names := range [][]domain.VLANMetadata{nil, {{SiteID: "site", ID: 120, Name: "Current staff"}}} {
		s := new(Store)
		if e := s.SetLegacyVLANs([]LegacyVLAN{{ProviderID: "p", SiteID: "site", ObservedAt: domain.Unix(now.Add(-time.Minute)), Names: map[int]string{120: "Historical staff"}, Provenance: "legacy-config-bound"}}); e != nil {
			t.Fatal(e)
		}
		batch := domain.NetworkSnapshot{ProviderID: "p", Scope: domain.InventoryScope{ProviderID: "p", IDs: []string{"site"}}, Scopes: []domain.NetworkScopeResult{{ScopeID: "site", Status: domain.CapabilityAvailable, ObservedAt: domain.Unix(now), VLANStatus: domain.CapabilityAvailable, VLANObservedAt: domain.Unix(now)}}, VLANs: names}
		if e := s.Publish(batch); e != nil {
			t.Fatal(e)
		}
		want := ""
		if len(names) > 0 {
			want = "Current staff"
		}
		got := s.Resolve("p", "site", "", 120, now, time.Hour)
		if got.VLAN != want || got.Provenance != "" {
			t.Fatalf("authenticated current generation did not supersede legacy: %#v", got)
		}
	}
}
