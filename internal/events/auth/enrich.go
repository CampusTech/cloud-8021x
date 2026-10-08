package auth

import (
	"strconv"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/network"
)

// Enricher binds local display lookups to configured client/location scope. NAS
// names and addresses cannot choose a provider, site, policy, or device identity.
func Enricher(cfg config.Config, key []byte, snapshots *domain.SnapshotStore, metadata *network.Store) func(*Event, Record) {
	inventory := InventoryEnricher(key, snapshots, cfg.Policy.InventoryMaxAge)
	locations := map[string]config.Location{}
	for _, location := range cfg.Network.Locations {
		locations[location.ID] = location
	}
	clients := map[string]string{}
	for _, client := range cfg.RadiusClients {
		clients[client.ID] = client.LocationID
	}
	return func(e *Event, r Record) {
		location, ok := locations[clients[e.Client]]
		if !ok || location.ID != e.Location {
			return
		}
		inventory(e, r)
		if metadata == nil {
			return
		}
		vlan, _ := strconv.Atoi(e.VLANID)
		called := ""
		if len(r.Values["C8021X-Called"]) == 1 {
			called = e.Called
		}
		display := metadata.Resolve(location.ProviderID, location.SiteID, called, vlan, time.Now(), cfg.Policy.InventoryMaxAge)
		if display.Site != "" {
			e.SiteName = display.Site
		}
		if display.Authenticator != "" {
			e.APName = display.Authenticator
		}
		if display.VLAN != "" {
			e.VLANName = display.VLAN
		}
	}
}

// InventoryEnricher never treats certificate names or unverified Class as identity.
// Mutable local display data cannot alter the signed original VLAN.
func InventoryEnricher(key []byte, snapshots *domain.SnapshotStore, maxAge time.Duration) func(*Event, Record) {
	retained := append([]byte(nil), key...)
	return func(e *Event, r Record) {
		stations := r.Values["C8021X-Station"]
		counts := r.Values["C8021X-Station-Count"]
		if len(stations) != 1 || len(counts) != 1 || counts[0] != "1" {
			return
		}
		attribution := binding.Verify(retained, r.Values["Class"], e.Location, stations, e.Received, binding.MaxAge)
		if attribution == nil {
			return
		}
		e.DeviceID = string(attribution.DeviceID)
		e.Fingerprint = attribution.Fingerprint
		if attribution.VLAN != nil {
			e.VLANID = strconv.Itoa(*attribution.VLAN)
		}
		if snapshots == nil {
			return
		}
		view := snapshots.View()
		if !domain.Fresh(view.Updated(), time.Now(), maxAge) {
			return
		}
		if m := view.MetadataFor(attribution.DeviceID); m != nil {
			if m.Owner != "" {
				e.DeviceOwner = m.Owner
			}
			if m.Name != "" {
				e.DeviceName = m.Name
			}
			if m.Model != "" {
				e.DeviceModel = m.Model
			}
		}
	}
}
