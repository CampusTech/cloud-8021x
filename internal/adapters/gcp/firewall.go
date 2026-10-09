package gcp

import (
	"context"
	"errors"
	"net/http"
	"net/netip"

	"github.com/CampusTech/cloud-8021x/internal/network"

	"github.com/CampusTech/cloud-8021x/internal/privileged/sources"
)

// Firewall permits only the existing node-specific discovery rule; it cannot
// create rules, change networks/ports/targets or expose an arbitrary cloud URL.
type Firewall struct {
	client *Client
	target sources.FirewallTarget
}

func (c *Client) Firewall(target sources.FirewallTarget) (*Firewall, error) {
	if (c.projectID != "" && target.Project != c.projectID) || target.Validate() != nil {
		return nil, errors.New("invalid fixed firewall target")
	}
	return &Firewall{client: c, target: target}, nil
}
func (f *Firewall) endpoint() string {
	return "https://compute.googleapis.com/compute/v1/projects/" + f.target.Project + "/global/firewalls/allow-" + f.target.Node + "-discovered"
}
func (f *Firewall) Read(ctx context.Context) (sources.FirewallRule, error) {
	var out struct {
		Name, Network, Direction                                                           string
		Disabled                                                                           bool
		SourceRanges, TargetTags, SourceTags, SourceServiceAccounts, TargetServiceAccounts []string
		Allowed, Denied                                                                    []struct {
			Protocol string `json:"IPProtocol"`
			Ports    []string
		}
	}
	if e := f.client.request(ctx, http.MethodGet, f.endpoint(), nil, &out); e != nil {
		return sources.FirewallRule{}, e
	}
	r := sources.FirewallRule{Name: out.Name, Network: out.Network, Direction: out.Direction, Disabled: out.Disabled, SourceRanges: out.SourceRanges, TargetTags: out.TargetTags, SourceTags: out.SourceTags, SourceServiceAccounts: out.SourceServiceAccounts, TargetServiceAccounts: out.TargetServiceAccounts}
	for _, p := range out.Allowed {
		r.Allowed = append(r.Allowed, sources.Port{Protocol: p.Protocol, Ports: p.Ports})
	}
	for _, p := range out.Denied {
		r.Denied = append(r.Denied, sources.Port{Protocol: p.Protocol, Ports: p.Ports})
	}
	return r, nil
}
func (f *Firewall) Patch(ctx context.Context, state sources.FirewallState) error {
	if len(state.SourceRanges) > 2048 || (!state.Disabled && len(state.SourceRanges) == 0) {
		return errors.New("unbounded source firewall patch")
	}
	seen := map[string]bool{}
	for _, raw := range state.SourceRanges {
		prefix, e := netip.ParsePrefix(raw)
		if e != nil || prefix.Bits() != 32 || prefix.String() != raw || seen[raw] || (!network.PublicIPv4(prefix.Addr()) && (!state.Disabled || raw != "192.0.2.1/32")) {
			return errors.New("unsafe source firewall patch")
		}
		seen[raw] = true
	}
	return f.client.request(ctx, http.MethodPatch, f.endpoint(), struct {
		SourceRanges []string `json:"sourceRanges"`
		Disabled     bool     `json:"disabled"`
	}{state.SourceRanges, state.Disabled}, nil)
}
