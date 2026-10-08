package network

import (
	"errors"
	"math"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

type LegacyVLAN struct {
	ProviderID, SiteID, Provenance string
	ObservedAt                     domain.Timestamp
	Names                          map[int]string
}

// SetLegacyVLANs is an explanatory fallback, never a provider cache or source
// authority. The caller has matched retained legacy config to current scope.
func (s *Store) SetLegacyVLANs(rows []LegacyVLAN) error {
	if len(rows) > 128 {
		return errors.New("legacy display exceeds bound")
	}
	idx := &index{scopes: map[string]scopeData{}}
	for _, r := range rows {
		key := scopeKey(r.ProviderID, r.SiteID)
		if !Name(r.ProviderID) || !Name(r.SiteID) || r.Provenance != "legacy-config-bound" || r.ObservedAt <= 0 || math.IsInf(float64(r.ObservedAt), 0) || math.IsNaN(float64(r.ObservedAt)) || len(r.Names) > 4094 {
			return errors.New("invalid legacy display")
		}
		if _, exists := idx.scopes[key]; exists {
			return errors.New("ambiguous legacy display scope")
		}
		names := map[int]string{}
		for id, name := range r.Names {
			if !domain.ValidVLAN(id) || !Name(name) {
				return errors.New("invalid legacy VLAN label")
			}
			names[id] = name
		}
		idx.scopes[key] = scopeData{at: r.ObservedAt, vlanAt: r.ObservedAt, vlans: names}
	}
	s.legacy.Store(idx)
	return nil
}
func (s *Store) legacyVLAN(provider, site string, vlan int, now time.Time, maxAge time.Duration) Metadata {
	if maxAge > time.Hour {
		maxAge = time.Hour
	} // Retained legacy VLAN cache contract.
	idx := s.legacy.Load()
	if idx == nil {
		return Metadata{}
	}
	d := idx.scopes[scopeKey(provider, site)]
	if !domain.Fresh(d.at, now, maxAge) {
		return Metadata{}
	}
	return Metadata{VLAN: d.vlans[vlan], ObservedAt: d.at, Provenance: "legacy-config-bound"}
}
