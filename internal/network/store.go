// Package network owns local, provider-neutral display metadata, never policy trust.
package network

import (
	"errors"
	"math"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

type Metadata struct {
	Provenance                string
	Site, Authenticator, VLAN string
	ObservedAt                domain.Timestamp
}
type scopeData struct {
	vlanAt domain.Timestamp
	at     domain.Timestamp
	site   string
	macs   map[string]string
	vlans  map[int]string
	ports  map[string][]string
}
type index struct{ scopes map[string]scopeData }
type Store struct {
	mu      sync.Mutex
	current atomic.Pointer[index]
	legacy  atomic.Pointer[index]
}

func scopeKey(provider, site string) string { return provider + "\x00" + site }

var macPattern = regexp.MustCompile(`^(?:[0-9a-fA-F]{12}|(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}|(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}|(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4})(?::.*)?$`)

func MAC(raw string) string {
	if !macPattern.MatchString(raw) {
		return ""
	}
	out := ""
	for _, c := range raw {
		if c == ':' || c == '-' || c == '.' {
			continue
		}
		out += string(c)
		if len(out) == 12 {
			return strings.ToUpper(out)
		}
	}
	return ""
}
func Name(s string) bool {
	if s == "" || len(s) > 255 || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func Validate(b domain.NetworkSnapshot) error {
	if !Name(b.ProviderID) || b.Scope.ProviderID != b.ProviderID || len(b.Scope.IDs) == 0 || len(b.Scope.IDs) > 128 || len(b.Authenticators) > 20000 || len(b.VLANs) > 20000 {
		return errors.New("invalid metadata provider scope")
	}
	want := map[string]bool{}
	for _, id := range b.Scope.IDs {
		if !Name(id) || want[id] {
			return errors.New("invalid metadata scopes")
		}
		want[id] = true
	}
	seen := map[string]bool{}
	for _, s := range b.Scopes {
		if !want[s.ScopeID] || seen[s.ScopeID] || (s.Status != domain.CapabilityAvailable && s.Status != domain.CapabilityFailed && s.Status != domain.CapabilityUnsupported) {
			return errors.New("invalid metadata scope result")
		}
		if s.Status == domain.CapabilityAvailable && (s.ObservedAt <= 0 || math.IsNaN(float64(s.ObservedAt)) || math.IsInf(float64(s.ObservedAt), 0)) {
			return errors.New("invalid metadata observation time")
		}
		if s.VLANStatus != "" && s.VLANStatus != domain.CapabilityAvailable && s.VLANStatus != domain.CapabilityFailed && s.VLANStatus != domain.CapabilityUnsupported {
			return errors.New("invalid VLAN capability status")
		}
		if s.VLANStatus == domain.CapabilityAvailable && (s.VLANObservedAt <= 0 || math.IsNaN(float64(s.VLANObservedAt)) || math.IsInf(float64(s.VLANObservedAt), 0)) {
			return errors.New("invalid VLAN observation time")
		}
		seen[s.ScopeID] = true
	}
	if len(seen) != len(want) {
		return domain.ErrIncompleteSnapshot
	}
	for _, a := range b.Authenticators {
		if !want[a.SiteID] || a.ID == "" {
			return errors.New("out of scope authenticator")
		}
	}
	for _, v := range b.VLANs {
		if !want[v.SiteID] {
			return errors.New("out of scope VLAN")
		}
	}
	for _, s := range b.Sites {
		if !want[s.ID] {
			return errors.New("out of scope site")
		}
	}
	return nil
}
func (s *Store) Publish(b domain.NetworkSnapshot) error {
	if err := Validate(b); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := &index{scopes: map[string]scopeData{}}
	if old := s.current.Load(); old != nil {
		for k, v := range old.scopes {
			next.scopes[k] = v
		}
	}
	for _, r := range b.Scopes {
		if r.Status != domain.CapabilityAvailable {
			continue
		}
		key := scopeKey(b.ProviderID, r.ScopeID)
		if old, ok := next.scopes[key]; ok && old.at > r.ObservedAt {
			continue
		}
		d := scopeData{at: r.ObservedAt, macs: map[string]string{}, vlans: map[int]string{}, ports: map[string][]string{}}
		owners := map[string]string{}
		for _, site := range b.Sites {
			if site.ID == r.ScopeID && Name(site.Name) {
				if d.site != "" && d.site != site.Name {
					d.site = ""
					break
				}
				d.site = site.Name
			}
		}
		for _, a := range b.Authenticators {
			if a.SiteID != r.ScopeID || !Name(a.Name) {
				continue
			}
			d.ports[a.ID] = append([]string(nil), a.Ports...)
			for _, raw := range append([]string{a.HardwareMAC}, a.MACs...) {
				m := MAC(raw)
				if m == "" {
					continue
				}
				if owner, exists := owners[m]; exists && (owner != a.ID || d.macs[m] != a.Name) {
					owners[m] = ""
					d.macs[m] = ""
				} else if !exists {
					owners[m] = a.ID
					d.macs[m] = a.Name
				}
			}
		}

		inferredOwners := map[string]string{}
		inferredNames := map[string]string{}
		for _, a := range b.Authenticators {
			if a.SiteID != r.ScopeID || !Name(a.Name) {
				continue
			}
			for _, raw := range a.InferredMACs {
				m := MAC(raw)
				if m == "" {
					continue
				}
				if _, exact := owners[m]; exact {
					continue
				}
				if owner, exists := inferredOwners[m]; exists && (owner != a.ID || inferredNames[m] != a.Name) {
					inferredOwners[m] = ""
					inferredNames[m] = ""
				} else if !exists {
					inferredOwners[m] = a.ID
					inferredNames[m] = a.Name
				}
			}
		}
		for mac, name := range inferredNames {
			d.macs[mac] = name
		}
		for _, v := range b.VLANs {
			if v.SiteID != r.ScopeID || !domain.ValidVLAN(v.ID) || !Name(v.Name) {
				continue
			}
			if old, ok := d.vlans[v.ID]; ok && old != v.Name {
				d.vlans[v.ID] = ""
			} else if !ok {
				d.vlans[v.ID] = v.Name
			}
		}
		if r.VLANStatus == domain.CapabilityFailed || r.VLANStatus == domain.CapabilityUnsupported {
			if old, ok := next.scopes[key]; ok {
				d.vlans = old.vlans
				d.vlanAt = old.vlanAt
			}
		} else {
			d.vlanAt = r.VLANObservedAt
			if d.vlanAt == 0 {
				d.vlanAt = r.ObservedAt
			}
		}
		next.scopes[key] = d
	}
	s.current.Store(next)
	return nil
}
func (s *Store) Resolve(provider, site, calledStation string, vlan int, now time.Time, maxAge time.Duration) Metadata {
	idx := s.current.Load()
	if idx == nil {
		return s.legacyVLAN(provider, site, vlan, now, maxAge)
	}
	d, ok := idx.scopes[scopeKey(provider, site)]
	if !ok || !domain.Fresh(d.at, now, maxAge) {
		return s.legacyVLAN(provider, site, vlan, now, maxAge)
	}
	vlanName := ""
	if domain.Fresh(d.vlanAt, now, maxAge) {
		vlanName = d.vlans[vlan]
	}
	result := Metadata{Site: d.site, Authenticator: d.macs[MAC(calledStation)], VLAN: vlanName, ObservedAt: d.at}
	if !domain.Fresh(d.vlanAt, now, maxAge) {
		legacy := s.legacyVLAN(provider, site, vlan, now, maxAge)
		result.VLAN, result.Provenance = legacy.VLAN, legacy.Provenance
	}
	return result
}
func (s *Store) Ports(provider, site, id string, now time.Time, maxAge time.Duration) []string {
	idx := s.current.Load()
	if idx == nil {
		return nil
	}
	d := idx.scopes[scopeKey(provider, site)]
	if !domain.Fresh(d.at, now, maxAge) {
		return nil
	}
	return append([]string(nil), d.ports[id]...)
}

type Registration struct {
	Identity  string
	ID        string
	Inventory domain.NetworkInventoryProvider
	Signaler  domain.VLANSignaler
	Discovery domain.SourceDiscoveryProvider
	Scope     domain.InventoryScope
}
type Registry struct{ Entries []Registration }

func NewRegistry(entries []Registration) (*Registry, error) {
	seen := map[string]bool{}
	for _, r := range entries {
		if r.ID == "" || seen[r.ID] || r.Inventory == nil || r.Scope.ProviderID != r.ID || len(r.Scope.IDs) == 0 {
			return nil, errors.New("invalid network registration")
		}
		seen[r.ID] = true
	}
	return &Registry{Entries: append([]Registration(nil), entries...)}, nil
}

// Replace publishes a complete configured document in one atomic pointer swap.
func (s *Store) Replace(batches []domain.NetworkSnapshot) error {
	temporary := new(Store)
	for _, b := range batches {
		if e := temporary.Publish(b); e != nil {
			return e
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current.Store(temporary.current.Load())
	return nil
}
