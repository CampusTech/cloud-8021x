package network

import (
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

func TestPublicationIsolationAndOriginalTime(t *testing.T) {
	s := new(Store)
	now := time.Now()
	scope := domain.InventoryScope{ProviderID: "one", IDs: []string{"office", "home"}}
	first := domain.NetworkSnapshot{ProviderID: "one", Scope: scope, Scopes: []domain.NetworkScopeResult{{ScopeID: "office", Status: domain.CapabilityAvailable, ObservedAt: domain.Unix(now)}, {ScopeID: "home", Status: domain.CapabilityUnsupported}}, Sites: []domain.NetworkSite{{ID: "office", Name: "32 Avenue of the Americas"}}, Authenticators: []domain.Authenticator{{ID: "one/office/ap", SiteID: "office", HardwareMAC: "aabbccddeeff", Name: "AP"}}, VLANs: []domain.VLANMetadata{{SiteID: "office", ID: 10, Name: "Staff"}}}
	if err := s.Publish(first); err != nil {
		t.Fatal(err)
	}
	got := s.Resolve("one", "office", "AA-BB-CC-DD-EE-FF:Campus", 10, now, time.Hour)
	if got.Authenticator != "AP" || got.Site != "32 Avenue of the Americas" || got.VLAN != "Staff" {
		t.Fatalf("missing metadata: %+v", got)
	}
	first.Scopes[0].Status = domain.CapabilityFailed
	first.Scopes[0].ObservedAt = domain.Unix(now.Add(time.Minute))
	first.Authenticators = nil
	first.VLANs = nil
	if err := s.Publish(first); err != nil {
		t.Fatal(err)
	}
	if s.Resolve("one", "office", "AABBCCDDEEFF", 10, now.Add(2*time.Hour), time.Hour).VLAN != "" {
		t.Fatal("failed refresh freshened old names")
	}
	if s.Resolve("other", "office", "AABBCCDDEEFF", 10, now, time.Hour).VLAN != "" {
		t.Fatal("provider collision")
	}
}
func TestCollisionTombstones(t *testing.T) {
	s := new(Store)
	now := time.Now()
	b := domain.NetworkSnapshot{ProviderID: "p", Scope: domain.InventoryScope{ProviderID: "p", IDs: []string{"s"}}, Scopes: []domain.NetworkScopeResult{{ScopeID: "s", Status: domain.CapabilityAvailable, ObservedAt: domain.Unix(now)}}, Authenticators: []domain.Authenticator{{ID: "a", SiteID: "s", HardwareMAC: "AABBCCDDEEFF", Name: "Same"}, {ID: "b", SiteID: "s", HardwareMAC: "AABBCCDDEEFF", Name: "Same"}, {ID: "a", SiteID: "s", HardwareMAC: "AABBCCDDEEFF", Name: "Same"}}}
	if err := s.Publish(b); err != nil {
		t.Fatal(err)
	}
	if s.Resolve("p", "s", "AABBCCDDEEFF", 0, now, time.Hour).Authenticator != "" {
		t.Fatal("ambiguous MAC reintroduced")
	}
}
func TestFailedVLANRefreshCannotEraseOrFreshenLabel(t *testing.T) {
	now := time.Now()
	s := new(Store)
	scope := domain.InventoryScope{ProviderID: "p", IDs: []string{"s"}}
	b := domain.NetworkSnapshot{ProviderID: "p", Scope: scope, Scopes: []domain.NetworkScopeResult{{ScopeID: "s", Status: domain.CapabilityAvailable, ObservedAt: domain.Unix(now), VLANStatus: domain.CapabilityAvailable, VLANObservedAt: domain.Unix(now)}}, VLANs: []domain.VLANMetadata{{SiteID: "s", ID: 20, Name: "Staff"}}}
	if e := s.Publish(b); e != nil {
		t.Fatal(e)
	}
	b.Scopes[0].ObservedAt = domain.Unix(now.Add(time.Minute))
	b.Scopes[0].VLANStatus = domain.CapabilityFailed
	b.VLANs = nil
	if e := s.Publish(b); e != nil {
		t.Fatal(e)
	}
	if s.Resolve("p", "s", "", 20, now.Add(time.Minute), time.Hour).VLAN != "Staff" {
		t.Fatal("failed VLAN erased successful label")
	}
	if s.Resolve("p", "s", "", 20, now.Add(time.Hour), time.Hour).VLAN != "" {
		t.Fatal("AP refresh prolonged VLAN freshness")
	}
}
func TestProviderAndSiteIDsDoNotCollideDuringConcurrentReads(t *testing.T) {
	now := time.Now()
	s := new(Store)
	done := make(chan struct{})
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			select {
			case <-done:
				return
			default:
				_ = s.Resolve("p", "one", "AABBCCDDEEFF", 10, now, time.Hour)
			}
		}
	}()
	defer func() { close(done); <-readDone }()
	for _, entry := range []struct{ provider, site, label string }{{"p", "one", "First"}, {"p", "two", "Second"}, {"q", "one", "Third"}} {
		b := domain.NetworkSnapshot{ProviderID: entry.provider, Scope: domain.InventoryScope{ProviderID: entry.provider, IDs: []string{entry.site}}, Scopes: []domain.NetworkScopeResult{{ScopeID: entry.site, Status: domain.CapabilityAvailable, ObservedAt: domain.Unix(now)}}, Authenticators: []domain.Authenticator{{ID: entry.provider + "/" + entry.site + "/ap", SiteID: entry.site, HardwareMAC: "AABBCCDDEEFF", Name: entry.label}}, VLANs: []domain.VLANMetadata{{SiteID: entry.site, ID: 10, Name: entry.label}}}
		if e := s.Publish(b); e != nil {
			t.Fatal(e)
		}
	}
	for _, entry := range []struct{ provider, site, label string }{{"p", "one", "First"}, {"p", "two", "Second"}, {"q", "one", "Third"}} {
		got := s.Resolve(entry.provider, entry.site, "AABBCCDDEEFF", 10, now, time.Hour)
		if got.Authenticator != entry.label || got.VLAN != entry.label {
			t.Fatal("provider/site collision", got)
		}
	}
}
func TestExactMACPrecedenceAndInferredAliasCollisionTombstones(t *testing.T) {
	now := time.Now()
	s := new(Store)
	b := domain.NetworkSnapshot{ProviderID: "u", Scope: domain.InventoryScope{ProviderID: "u", IDs: []string{"office"}}, Scopes: []domain.NetworkScopeResult{{ScopeID: "office", Status: domain.CapabilityAvailable, ObservedAt: domain.Unix(now)}}, Authenticators: []domain.Authenticator{{ID: "u/office/a", SiteID: "office", HardwareMAC: "AABBCCDDEE01", Name: "First", InferredMACs: []string{"AABBCCDDEE02", "AABBCCDDEE04", "AABBCCDDEE05"}}, {ID: "u/office/b", SiteID: "office", HardwareMAC: "AABBCCDDEE04", Name: "Second", InferredMACs: []string{"AABBCCDDEE05"}}, {ID: "u/office/a", SiteID: "office", HardwareMAC: "AABBCCDDEE01", Name: "First", InferredMACs: []string{"AABBCCDDEE05"}}}}
	if e := s.Publish(b); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct{ mac, want string }{{"AABBCCDDEE02", "First"}, {"AABBCCDDEE04", "Second"}, {"AABBCCDDEE05", ""}} {
		if got := s.Resolve("u", "office", tc.mac, 0, now, time.Hour).Authenticator; got != tc.want {
			t.Fatalf("%s got %q want %q", tc.mac, got, tc.want)
		}
	}
}
