package app

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strconv"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/migration"
	"github.com/CampusTech/cloud-8021x/internal/network"
)

const legacyDisplayPath = "/etc/cloud-8021x/legacy-display.json"

type legacyDisplayDocument struct {
	ConfigSHA256, BundleSHA256, Provenance string
	VLANs                                  []network.LegacyVLAN
}

func deriveLegacyDisplay(cfg config.Config, b migration.Bundle) ([]network.LegacyVLAN, error) {
	out := []network.LegacyVLAN{}
	if b.VLANSources == nil || len(b.VLANs) == 0 {
		return out, nil
	}
	var pinned map[string]migration.LegacyVLANSource
	var cache struct {
		Locations map[string]struct {
			Source  migration.LegacyVLANSource `json:"source"`
			Updated json.Number                `json:"updated_at"`
			Names   map[string]string          `json:"names"`
		} `json:"locations"`
	}
	if domain.DecodeJSONStrict(b.VLANSources.Data, &pinned) != nil || domain.DecodeJSONStrict(b.VLANs, &cache) != nil {
		return nil, errors.New("invalid retained VLAN display source")
	}
	for _, location := range cfg.Network.Locations {
		original, ok := pinned[location.ID]
		row, present := cache.Locations[location.ID]
		if !ok || !present || original != row.Source || original.UniFiHostID == "" || original.UniFiSiteID == "" {
			continue
		}
		// Legacy Meraki did not retain organization identity, and AP caches did not
		// retain console/site identifiers. Their raw originals remain unavailable.
		for _, provider := range cfg.Network.Providers {
			if provider.ID != location.ProviderID || provider.Kind != "unifi" || provider.BaseURL != "https://api.ui.com/v1" || provider.ConsoleID != original.UniFiHostID || location.SiteID != original.UniFiSiteID || !slices.Contains(provider.Scopes, location.SiteID) {
				continue
			}
			at, e := migration.ReceiptTime([]byte(row.Updated))
			if e != nil {
				return nil, e
			}
			names := map[int]string{}
			for raw, name := range row.Names {
				id, e := strconv.Atoi(raw)
				if e != nil || !domain.ValidVLAN(id) || !network.Name(name) {
					return nil, errors.New("invalid original VLAN label")
				}
				names[id] = name
			}
			out = append(out, network.LegacyVLAN{ProviderID: provider.ID, SiteID: location.SiteID, Names: names, ObservedAt: domain.Unix(at), Provenance: "legacy-config-bound"})
		}
	}
	return out, nil
}
func loadLegacyDisplay(cfg config.Config, store *network.Store) error {
	if _, e := os.Lstat(legacyDisplayPath); os.IsNotExist(e) {
		return nil
	} else if e != nil {
		return e
	}
	raw, e := readInventoryFile(legacyDisplayPath, false, 1<<20)
	if e != nil {
		return e
	}
	var document legacyDisplayDocument
	_, hash, e := transitionBinding(cfg)
	if e != nil {
		return e
	}
	if domain.DecodeJSONStrict(raw, &document) != nil || document.Provenance != "legacy-config-bound" || len(document.BundleSHA256) != 64 {
		return errors.New("invalid legacy display document")
	}
	if document.ConfigSHA256 != hash {
		return nil
	}
	return store.SetLegacyVLANs(document.VLANs)
}
