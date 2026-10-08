package telemetry

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/events/auth"
	"github.com/CampusTech/cloud-8021x/internal/network"
)

func TestDisplayFreshnessIndependentAcrossInventoryNetworkAndDiscovery(t *testing.T) {
	now := time.Now()
	snapshots := new(domain.SnapshotStore)
	snapshot, err := domain.BuildSnapshot([]domain.Device{{ID: "test:1", Groups: []domain.GroupID{}, Metadata: &domain.DeviceMetadata{Owner: "Owner"}}}, domain.Unix(now.Add(-10*time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	if err = snapshots.Set(snapshot); err != nil {
		t.Fatal(err)
	}
	metadata := new(network.Store)
	if err = metadata.Publish(domain.NetworkSnapshot{ProviderID: "p", Scope: domain.InventoryScope{ProviderID: "p", IDs: []string{"site"}}, Scopes: []domain.NetworkScopeResult{{ScopeID: "site", Status: domain.CapabilityAvailable, ObservedAt: domain.Unix(now.Add(-10 * time.Minute))}}, Sites: []domain.NetworkSite{{ID: "site", Name: "Office"}}}); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte("k"), 32)
	id := binding.Attribution{DeviceID: "test:1", Fingerprint: strings.Repeat("a", 64)}
	token, err := binding.Issue(key, id, "nyc", "aa:bb:cc:dd:ee:ff", now)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name               string
		inventory, network time.Duration
		owner, site        string
	}{
		{"inventory expired", time.Minute, time.Hour, "N/A", "Office"},
		{"network expired", time.Hour, time.Minute, "Owner", "N/A"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Policy.InventoryMaxAge = tc.inventory
			cfg.Network.MetadataMaxAge = tc.network
			cfg.Network.Discovery.MaxAge = time.Second
			cfg.Network.Locations = []config.Location{{ID: "nyc", ProviderID: "p", SiteID: "site"}}
			cfg.RadiusClients = []config.RadiusClient{{ID: "office", LocationID: "nyc"}}
			r := BusinessRecord{Fields: map[string]any{"device_owner": "N/A", "site_name": "N/A"}}
			NewDisplay(cfg, snapshots, metadata).Enrich(&r, "nyc", "", &id)
			if r.Fields["device_owner"] != tc.owner || r.Fields["site_name"] != tc.site {
				t.Fatal(r.Fields)
			}
			e := auth.Event{Client: "office", Location: "nyc", Received: now, DeviceOwner: "N/A", SiteName: "N/A"}
			auth.Enricher(cfg, key, snapshots, metadata)(&e, auth.Record{Values: map[string][]string{"Class": {token}, "C8021X-Station": {"aa:bb:cc:dd:ee:ff"}, "C8021X-Station-Count": {"1"}}})
			if e.DeviceOwner != tc.owner || e.SiteName != tc.site || e.DeviceID != "test:1" {
				t.Fatal(e)
			}
		})
	}
}
