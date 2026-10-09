package main

import (
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/network"
	"github.com/CampusTech/cloud-8021x/internal/telemetry"
)

// The two fixed synthetic API hosts intentionally supply no optional display
// data. Prove the actual renderer is freshness-insensitive for that exact scope;
// meaningful names/serials or non-neutral network metadata require historical evidence.
func semanticDisplay(c config.Config, s domain.Snapshot, metadata ...domain.NetworkSnapshot) (string, error) {
	if (len(c.Network.Providers) != 0 && !neutralNetworkScope(c)) || c.Policy.InventoryMaxAge < time.Second {
		return "", errors.New("display source scope differs")
	}
	for id, m := range s.Devices {
		if id != "fleet:1" && id != "fleet:2" {
			return "", errors.New("display identity outside reviewed seed")
		}
		if m == nil {
			continue
		}
		for _, v := range []string{m.Serial, m.Name, m.Model, m.Owner} {
			if v != "" && v != "N/A" {
				return "", errors.New("meaningful display changes need exact historical send context")
			}
		}
	}
	expected := map[string]any{"device_owner": "N/A", "device_name": "N/A", "device_model": "N/A", "serial": "N/A", "site_name": "N/A", "ap_name": "N/A", "vlan_name": "N/A", "vlan_id": "120"}
	stores := []*network.Store{nil, new(network.Store)}
	if len(metadata) > 1 || len(metadata) > 0 && !neutralNetworkScope(c) {
		return "", errors.New("unexpected network metadata scope")
	}
	for _, batch := range metadata {
		if err := validateNeutralMetadata(batch); err != nil {
			return "", err
		}
		for _, at := range []domain.Timestamp{batch.Scopes[0].ObservedAt, domain.Unix(time.Now().Add(-time.Millisecond)), domain.Unix(time.Now().Add(-48 * time.Hour))} {
			copy := batch
			copy.Scopes = append([]domain.NetworkScopeResult(nil), batch.Scopes...)
			copy.Scopes[0].ObservedAt = at
			copy.Scopes[0].VLANObservedAt = at
			store := new(network.Store)
			if err := store.Publish(copy); err != nil {
				return "", err
			}
			stores = append(stores, store)
		}
	}
	for _, id := range []domain.DeviceID{"fleet:1", "fleet:2"} {
		for _, stamp := range []domain.Timestamp{s.UpdatedAt, domain.Unix(time.Now().Add(-time.Millisecond)), 0} {
			snapshot := s.Clone()
			snapshot.UpdatedAt = stamp
			store := &domain.SnapshotStore{}
			if err := store.Set(snapshot); err != nil {
				return "", err
			}
			for _, metadataStore := range stores {
				r := telemetry.BusinessRecord{Fields: map[string]any{}}
				for key, value := range expected {
					r.Fields[key] = value
				}
				vlan := 120
				telemetry.NewDisplay(c, store, metadataStore).Enrich(&r, "task11", "AA:BB:CC:DD:EE:FF", &binding.Attribution{DeviceID: id, VLAN: &vlan})
				if !reflect.DeepEqual(r.Fields, expected) {
					return "", errors.New("actual display freshness changes rendered fields")
				}
			}
		}
	}
	raw, err := json.Marshal(expected)
	if err != nil {
		return "", err
	}
	return adoption.Digest(raw), nil
}

// This is the sole synthetic metadata provider, not a general provider exception.
func neutralNetworkScope(c config.Config) bool {
	p := config.NetworkProvider{ID: "task11-unifi", Kind: "unifi", BaseURL: "https://unifi.task11.test/v1", ConsoleID: "task11-console", Scopes: []string{"task11-site"}, Credential: config.SecretRef{File: "/run/cloud-8021x/credentials/unifi-token"}, CacheFile: "/var/cache/cloud-8021x/runtime/task11-unifi.json", Timeout: 5 * time.Second}
	return reflect.DeepEqual(c.Network.Providers, []config.NetworkProvider{p}) && reflect.DeepEqual(c.Network.Locations, []config.Location{{ID: "task11", ProviderID: "task11-unifi", SiteID: "task11-site", VLANEnabled: true}}) && reflect.DeepEqual(c.RadiusClients, []config.RadiusClient{{ID: "task11-nas", CIDRs: []string{"10.203.11.40/32"}, LocationID: "task11", Medium: "wifi", SignalingProfile: "unifi-numeric", Secret: config.SecretRef{File: "/run/cloud-8021x-root/radius-task11-secret"}}}) && reflect.DeepEqual(c.Policy.Rules, []config.VLANRule{{GroupID: "fleet:1", LocationID: "task11", VLAN: 120}}) && !c.Network.Discovery.Enabled && len(c.Network.Discovery.Bindings) == 0 && c.Network.Discovery.Firewall == (config.SourceFirewall{}) && c.Network.MetadataMaxAge == time.Hour && c.Paths.MetadataFile == "/var/lib/cloud-8021x/metadata.json"
}
func validateNeutralMetadata(b domain.NetworkSnapshot) error {
	if err := network.Validate(b); err != nil {
		return err
	}
	if b.ProviderID != "task11-unifi" || !reflect.DeepEqual(b.Scope, domain.InventoryScope{ProviderID: "task11-unifi", IDs: []string{"task11-site"}}) || len(b.Scopes) != 1 || b.Scopes[0].ScopeID != "task11-site" || b.Scopes[0].Status != domain.CapabilityAvailable || b.Scopes[0].VLANStatus != domain.CapabilityAvailable || !reflect.DeepEqual(b.Sites, []domain.NetworkSite{{ID: "task11-site", Name: "N/A"}}) || len(b.Authenticators) != 0 || len(b.VLANs) != 0 {
		return errors.New("network metadata differs from independent neutral seed")
	}
	return nil
}
