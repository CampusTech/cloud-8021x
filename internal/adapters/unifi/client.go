// Package unifi normalizes pinned UniFi Cloud Connector inventory.
package unifi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/network/httpjson"
	"github.com/CampusTech/cloud-8021x/internal/adapters/network/signaling"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/network"
)

type Client struct {
	signaling.StandardNumeric
	ID, ConsoleID string
	HTTP          *httpjson.Client
	Now           func() time.Time
}

func New(id, base, key string, hc *http.Client, timeout time.Duration, now func() time.Time) (*Client, error) {
	if !httpjson.Segment(id) {
		return nil, errors.New("invalid UniFi provider ID")
	}
	h, e := httpjson.New(base, "X-API-Key", key, hc, timeout)
	return &Client{ID: id, HTTP: h, Now: now}, e
}
func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

type host struct {
	ID      string `json:"id"`
	IP      string `json:"ipAddress"`
	Blocked bool   `json:"isBlocked"`
	State   struct {
		WANs []struct {
			IPv4 string `json:"ipv4"`
		} `json:"wans"`
	} `json:"reportedState"`
}

func (c *Client) hosts(ctx context.Context) ([]host, error) {
	var all []host
	token := ""
	seen := map[string]bool{}
	for range httpjson.MaxPages {
		var p struct {
			Data []host `json:"data"`
			Next string `json:"nextToken"`
		}
		q := url.Values{"pageSize": {"100"}}
		if token != "" {
			q.Set("nextToken", token)
		}
		if _, err := c.HTTP.Get(ctx, c.HTTP.URL("/hosts?")+q.Encode(), &p); err != nil {
			return nil, err
		}
		if p.Data == nil {
			return nil, httpjson.ErrPagination
		}
		for _, h := range p.Data {
			if !httpjson.Segment(h.ID) || len(h.State.WANs) > 16 || len(h.IP) > 64 {
				return nil, httpjson.ErrPagination
			}
		}
		all = append(all, p.Data...)
		if len(all) > 20000 {
			return nil, httpjson.ErrPagination
		}
		if p.Next == "" {
			return all, nil
		}
		if seen[p.Next] || len(p.Next) > 2048 || strings.ContainsAny(p.Next, "\r\n") {
			return nil, httpjson.ErrPagination
		}
		seen[p.Next] = true
		token = p.Next
	}
	return nil, httpjson.ErrPagination
}
func (c *Client) DiscoverSources(ctx context.Context, scope domain.InventoryScope) ([]domain.SourceCandidate, error) {
	if scope.ProviderID != c.ID || len(scope.IDs) != 1 || !httpjson.Segment(scope.IDs[0]) || (c.ConsoleID != "" && scope.IDs[0] != c.ConsoleID) {
		return nil, errors.New("invalid pinned UniFi console scope")
	}
	hosts, err := c.hosts(ctx)
	if err != nil {
		return nil, err
	}
	var match *host
	for i := range hosts {
		if hosts[i].ID == scope.IDs[0] {
			if match != nil {
				return nil, errors.New("ambiguous UniFi console")
			}
			match = &hosts[i]
		}
	}
	if match == nil || match.Blocked {
		return nil, errors.New("pinned UniFi console unavailable")
	}
	addresses := []string{match.IP}
	for _, w := range match.State.WANs {
		addresses = append(addresses, w.IPv4)
	}
	set := map[string]bool{}
	for _, raw := range addresses {
		if raw == "" {
			continue
		}
		a, err := netip.ParseAddr(raw)
		if err != nil {
			return nil, errors.New("invalid UniFi WAN")
		}
		if network.PublicIPv4(a) {
			set[a.String()+"/32"] = true
		}
	}
	if len(set) == 0 {
		return nil, errors.New("UniFi console has no observed public IPv4 WAN")
	}
	cidrs := make([]string, 0, len(set))
	for s := range set {
		cidrs = append(cidrs, s)
	}
	sort.Strings(cidrs)
	return []domain.SourceCandidate{{ProviderID: c.ID, SiteID: scope.IDs[0], CIDRs: cidrs, ObservedAt: domain.Unix(c.now())}}, nil
}

type row struct {
	Features struct {
		AccessPoint *struct{} `json:"accessPoint"`
	} `json:"features"`
	ID         string `json:"id"`
	Name       string `json:"name"`
	MAC        string `json:"macAddress"`
	VLAN       *int   `json:"vlanId"`
	Interfaces struct {
		Ports []struct {
			Index int `json:"idx"`
		} `json:"ports"`
	} `json:"interfaces"`
}

func (c *Client) pages(ctx context.Context, path string) ([]row, error) {
	all := []row{}
	offset := 0
	total := -1
	seen := map[string]bool{}
	for range httpjson.MaxPages {
		var p struct {
			Data   []row `json:"data"`
			Offset *int  `json:"offset"`
			Count  *int  `json:"count"`
			Total  *int  `json:"totalCount"`
		}
		q := url.Values{"offset": {strconv.Itoa(offset)}, "limit": {"200"}}
		if _, err := c.HTTP.Get(ctx, c.HTTP.URL(path)+"?"+q.Encode(), &p); err != nil {
			return nil, err
		}
		if p.Data == nil || p.Offset == nil || p.Count == nil || p.Total == nil || *p.Offset != offset || *p.Count != len(p.Data) || *p.Total < 0 || *p.Total > 20000 {
			return nil, httpjson.ErrPagination
		}
		if total < 0 {
			total = *p.Total
		}
		if total != *p.Total || offset+len(p.Data) > total {
			return nil, httpjson.ErrPagination
		}
		for _, r := range p.Data {
			if !httpjson.Segment(r.ID) || seen[r.ID] {
				return nil, httpjson.ErrPagination
			}
			seen[r.ID] = true
		}
		all = append(all, p.Data...)
		offset += len(p.Data)
		if offset == total {
			return all, nil
		}
		if len(p.Data) == 0 {
			return nil, httpjson.ErrPagination
		}
	}
	return nil, httpjson.ErrPagination
}
func (c *Client) Fetch(ctx context.Context, scope domain.InventoryScope) (domain.NetworkSnapshot, error) {
	out := domain.NetworkSnapshot{ProviderID: c.ID, Scope: scope}
	if scope.ProviderID != c.ID || !httpjson.Segment(c.ConsoleID) || len(scope.IDs) == 0 {
		return out, errors.New("invalid UniFi inventory scope")
	}
	base := "/connector/consoles/" + url.PathEscape(c.ConsoleID) + "/proxy/network/integration/v1/sites"
	sites, err := c.pages(ctx, base)
	names := map[string]string{}
	for _, s := range sites {
		names[s.ID] = s.Name
	}
	seen := map[string]bool{}
	for _, id := range scope.IDs {
		if !httpjson.Segment(id) || seen[id] {
			return out, errors.New("invalid UniFi site scope")
		}
		seen[id] = true
		result := domain.NetworkScopeResult{ScopeID: id, Status: domain.CapabilityFailed}
		out.Scopes = append(out.Scopes, result)
		if err != nil || names[id] == "" {
			continue
		}
		devices, e := c.pages(ctx, base+"/"+url.PathEscape(id)+"/devices")
		if e != nil {
			continue
		}
		detailsOK := true
		for i, d := range devices {
			var detail row
			if _, e = c.HTTP.Get(ctx, c.HTTP.URL(base+"/"+url.PathEscape(id)+"/devices/"+url.PathEscape(d.ID)), &detail); e != nil || detail.ID != d.ID || !network.Name(detail.Name) || network.MAC(detail.MAC) == "" || len(detail.Interfaces.Ports) > 4096 {
				detailsOK = false
				break
			}
			devices[i] = detail
		}
		if !detailsOK {
			continue
		}
		vlans, e := c.pages(ctx, base+"/"+url.PathEscape(id)+"/networks")
		if e != nil {
			continue
		}
		valid := true
		for _, v := range vlans {
			if v.VLAN == nil || !network.Name(v.Name) {
				valid = false
			}
		}
		if !valid {
			continue
		}
		out.Scopes[len(out.Scopes)-1] = domain.NetworkScopeResult{ScopeID: id, Status: domain.CapabilityAvailable, ObservedAt: domain.Unix(c.now()), VLANStatus: domain.CapabilityAvailable, VLANObservedAt: domain.Unix(c.now())}
		out.Sites = append(out.Sites, domain.NetworkSite{ID: id, Name: names[id]})
		for _, d := range devices {
			a := domain.Authenticator{ID: c.ID + "/" + id + "/" + d.ID, SiteID: id, Name: d.Name, HardwareMAC: network.MAC(d.MAC)}
			if d.Features.AccessPoint != nil {
				a.InferredMACs = inferredBSSIDs(a.HardwareMAC)
			}
			for _, p := range d.Interfaces.Ports {
				if p.Index >= 0 {
					a.Ports = append(a.Ports, fmt.Sprint(p.Index))
				}
			}
			out.Authenticators = append(out.Authenticators, a)
		}
		for _, v := range vlans {
			out.VLANs = append(out.VLANs, domain.VLANMetadata{SiteID: id, ID: *v.VLAN, Name: v.Name})
		}
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	return out, nil
}

// Compile-time proof that hardware encoding never performs controller I/O.
var _ domain.VLANSignaler = (*Client)(nil)

// Preserve legacy UniFi display enrichment only: BSSIDs may be base MAC +1..7
// in the last byte. These are inferred, never advertised, never cross an octet,
// and the neutral resolver gives exact hardware/advertised MACs precedence.
func inferredBSSIDs(mac string) []string {
	if len(mac) != 12 {
		return nil
	}
	last, e := strconv.ParseUint(mac[10:], 16, 8)
	if e != nil {
		return nil
	}
	out := []string{}
	for offset := uint64(1); offset <= 7 && last+offset <= 255; offset++ {
		out = append(out, mac[:10]+fmt.Sprintf("%02X", last+offset))
	}
	return out
}
