package config

import (
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Validate new controller bindings when present; existing metadata-free policy
// fixtures remain loadable. Concrete sites/discovery factories require pins.
func validateNetworkDetails(c Config) error {
	providers := map[string]NetworkProvider{}
	unifiKey := ""
	for _, p := range c.Network.Providers {
		if !networkSegment(p.ID) {
			return errors.New("invalid network provider ID")
		}
		if p.ConsoleID != "" && !networkSegment(p.ConsoleID) || p.OrganizationID != "" && !networkSegment(p.OrganizationID) {
			return errors.New("invalid controller identifier")
		}
		if p.Kind == "unifi" {
			if unifiKey != "" && p.Credential.File != unifiKey {
				return errors.New("UniFi providers must share one API credential")
			}
			unifiKey = p.Credential.File
			if p.OrganizationID != "" {
				return errors.New("UniFi does not use organization_id")
			}
		} else if p.ConsoleID != "" {
			return errors.New("meraki does not use console_id")
		}
		seen := map[string]bool{}
		for _, id := range p.Scopes {
			if !networkSegment(id) || seen[id] {
				return errors.New("invalid or duplicate network scope")
			}
			seen[id] = true
		}
		if p.CacheFile != "" && (!filepath.IsAbs(p.CacheFile) || filepath.Clean(p.CacheFile) != p.CacheFile) {
			return errors.New("invalid network cache path")
		}
		providers[p.ID] = p
	}
	for _, l := range c.Network.Locations {
		p := providers[l.ProviderID]
		if p.ConsoleID == "" && p.OrganizationID == "" {
			continue
		}
		found := false
		for _, id := range p.Scopes {
			if id == l.SiteID {
				found = true
			}
		}
		if !found {
			return errors.New("location site_id must belong to the configured provider scopes")
		}
	}
	d := c.Network.Discovery
	if !d.Enabled {
		return nil
	}
	if len(d.Bindings) == 0 || !filepath.IsAbs(d.CandidateFile) || filepath.Clean(d.CandidateFile) != d.CandidateFile || d.MaxAge > time.Hour {
		return errors.New("source discovery requires bindings, private candidate path and max_age <= 1h")
	}
	if !regexp.MustCompile(`^[a-z][a-z0-9-]{4,62}$`).MatchString(d.Firewall.Project) || (!c.Parallel() && d.Firewall.Node != "radius-primary" && d.Firewall.Node != "radius-secondary") || !strings.HasPrefix(d.Firewall.Network, "https://www.googleapis.com/compute/v1/projects/"+d.Firewall.Project+"/") {
		return errors.New("source discovery requires a fixed project, node and network")
	}
	seenClients, seenConsoles := map[string]bool{}, map[string]bool{}
	for _, b := range d.Bindings {
		p := providers[b.ProviderID]
		if p.Kind != "unifi" || p.ConsoleID == "" || seenClients[b.ClientID] || seenConsoles[p.ConsoleID] {
			return errors.New("source bindings require unique pinned UniFi consoles and clients")
		}
		seenClients[b.ClientID] = true
		seenConsoles[p.ConsoleID] = true
		found := false
		for _, client := range c.RadiusClients {
			if client.ID == b.ClientID {
				for _, l := range c.Network.Locations {
					if l.ID == client.LocationID && l.ProviderID == b.ProviderID {
						found = true
					}
				}
			}
		}
		if !found {
			return errors.New("source binding must reference its configured provider client")
		}
	}
	return nil
}

func networkSegment(s string) bool {
	return s != "" && len(s) <= 255 && s != "." && s != ".." && !strings.ContainsAny(s, "/\\?%#\x00\r\n\t ")
}
