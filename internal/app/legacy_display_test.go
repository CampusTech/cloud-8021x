package app

import (
	"encoding/json"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/migration"
)

func TestLegacyDisplayRequiresRetainedExactOriginConsoleAndScope(t *testing.T) {
	cfg := config.Config{Network: config.Network{Providers: []config.NetworkProvider{{ID: "p", Kind: "unifi", BaseURL: "https://api.ui.com/v1", ConsoleID: "console", Scopes: []string{"site"}}}, Locations: []config.Location{{ID: "office", ProviderID: "p", SiteID: "site"}}}}
	b := migration.Bundle{VLANSources: &migration.LegacyFile{Data: json.RawMessage(`{"office":{"unifi_host_id":"console","unifi_site_id":"site"}}`), ModifiedAt: "1791453500.123456789"}, VLANs: json.RawMessage(`{"locations":{"office":{"source":{"unifi_host_id":"console","unifi_site_id":"site"},"updated_at":1791453600.125,"names":{"120":"Staff"}}}}`)}
	rows, e := deriveLegacyDisplay(cfg, b)
	if e != nil || len(rows) != 1 || rows[0].Names[120] != "Staff" || rows[0].ObservedAt != 1791453600.125 || rows[0].Provenance != "legacy-config-bound" {
		t.Fatal(rows, e)
	}
	for _, kind := range []string{"origin", "console", "site", "scope", "provider", "missing-config", "changed-original"} {
		t.Run(kind, func(t *testing.T) {
			changed := cfg
			changed.Network.Providers = append([]config.NetworkProvider(nil), cfg.Network.Providers...)
			changed.Network.Locations = append([]config.Location(nil), cfg.Network.Locations...)
			original := b
			switch kind {
			case "origin":
				changed.Network.Providers[0].BaseURL = "https://example.test/v1"
			case "console":
				changed.Network.Providers[0].ConsoleID = "other"
			case "site":
				changed.Network.Locations[0].SiteID = "other"
			case "scope":
				changed.Network.Providers[0].Scopes = []string{"other"}
			case "provider":
				changed.Network.Providers[0].Kind = "meraki"
			case "missing-config":
				original.VLANSources = nil
			case "changed-original":
				original.VLANSources = &migration.LegacyFile{Data: json.RawMessage(`{"office":{"unifi_host_id":"other","unifi_site_id":"site"}}`), ModifiedAt: "1791453500"}
			}
			rows, e := deriveLegacyDisplay(changed, original)
			if e != nil || len(rows) != 0 {
				t.Fatal("ambiguous legacy binding promoted", rows, e)
			}
		})
	}
}
