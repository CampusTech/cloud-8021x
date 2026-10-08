package auth

import (
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/network"
)

func TestNetworkEnrichmentUsesConfiguredScopeAndNeverGuessesDuplicateAP(t *testing.T) {
	cfg := config.Defaults()
	cfg.RadiusClients = []config.RadiusClient{{ID: "office", LocationID: "nyc"}}
	cfg.Network.Locations = []config.Location{{ID: "nyc", ProviderID: "p", SiteID: "site"}}
	store := new(network.Store)
	now := domain.Unix(time.Now())
	if err := store.Publish(domain.NetworkSnapshot{ProviderID: "p", Scope: domain.InventoryScope{ProviderID: "p", IDs: []string{"site"}}, Scopes: []domain.NetworkScopeResult{{ScopeID: "site", Status: domain.CapabilityAvailable, ObservedAt: now}}, Sites: []domain.NetworkSite{{ID: "site", Name: "Office"}}, Authenticators: []domain.Authenticator{{ID: "ap", SiteID: "site", Name: "Access point", HardwareMAC: "00:11:22:33:44:55"}}}); err != nil {
		t.Fatal(err)
	}
	enrich := Enricher(cfg, nil, nil, store)
	e := Event{Client: "office", Location: "nyc", Called: "00:11:22:33:44:55:SSID", APName: "N/A", SiteName: "N/A"}
	enrich(&e, Record{Values: map[string][]string{"C8021X-Called": {e.Called}}})
	if e.APName != "Access point" || e.SiteName != "Office" || e.DeviceID != "" {
		t.Fatal(e)
	}
	e.APName = "N/A"
	enrich(&e, Record{Values: map[string][]string{"C8021X-Called": {e.Called, e.Called}}})
	if e.APName != "N/A" {
		t.Fatal("ambiguous AP selected")
	}
	e.Location = "forged"
	e.SiteName = "N/A"
	enrich(&e, Record{})
	if e.SiteName != "N/A" {
		t.Fatal("packet selected metadata location")
	}
}
