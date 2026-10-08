// Package meraki supplies scoped Dashboard inventory and numeric VLAN signaling.
package meraki

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/network/httpjson"
	"github.com/CampusTech/cloud-8021x/internal/adapters/network/signaling"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/network"
)

type Client struct {
	signaling.StandardNumeric
	ID, OrganizationID string
	HTTP               *httpjson.Client
	Now                func() time.Time
}

func New(id, org, base, key string, hc *http.Client, timeout time.Duration) (*Client, error) {
	if !httpjson.Segment(id) || !httpjson.Segment(org) {
		return nil, errors.New("invalid Meraki provider organization")
	}
	h, e := httpjson.New(base, "Authorization", "Bearer "+key, hc, timeout)
	return &Client{ID: id, OrganizationID: org, HTTP: h}, e
}
func (c *Client) pages(ctx context.Context, path string, envelope bool) ([]json.RawMessage, error) {
	target := c.HTTP.URL(path)
	seen := map[string]bool{}
	all := []json.RawMessage{}
	bytes := 0
	for range httpjson.MaxPages {
		if seen[target] {
			return nil, httpjson.ErrPagination
		}
		seen[target] = true
		var raw json.RawMessage
		h, e := c.HTTP.Get(ctx, target, &raw)
		if e != nil {
			return nil, e
		}
		var rows []json.RawMessage
		if envelope {
			var p struct {
				Items []json.RawMessage `json:"items"`
			}
			if json.Unmarshal(raw, &p) != nil {
				return nil, httpjson.ErrPagination
			}
			rows = p.Items
		} else if json.Unmarshal(raw, &rows) != nil {
			return nil, httpjson.ErrPagination
		}
		if rows == nil {
			return nil, httpjson.ErrPagination
		}
		for _, r := range rows {
			bytes += len(r)
		}
		if bytes > httpjson.MaxBytes {
			return nil, httpjson.ErrPagination
		}
		all = append(all, rows...)
		if len(all) > 20000 {
			return nil, httpjson.ErrPagination
		}
		next, e := httpjson.Next(h, target)
		if e != nil {
			return nil, e
		}
		if next == "" {
			return all, nil
		}
		target = next
	}
	return nil, httpjson.ErrPagination
}

type device struct {
	Serial      string `json:"serial"`
	NetworkID   string `json:"networkId"`
	MAC         string `json:"mac"`
	Name        string `json:"name"`
	ProductType string `json:"productType"`
}
type status struct {
	Serial  string `json:"serial"`
	Name    string `json:"name"`
	Network struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"network"`
	BSS []struct {
		BSSID string `json:"bssid"`
	} `json:"basicServiceSets"`
}

func decode[T any](rows []json.RawMessage) ([]T, error) {
	out := make([]T, 0, len(rows))
	for _, r := range rows {
		var v T
		if len(r) == 0 || r[0] != '{' || json.Unmarshal(r, &v) != nil {
			return nil, errors.New("invalid Meraki record")
		}
		out = append(out, v)
	}
	return out, nil
}
func (c *Client) Fetch(ctx context.Context, scope domain.InventoryScope) (domain.NetworkSnapshot, error) {
	out := domain.NetworkSnapshot{ProviderID: c.ID, Scope: scope}
	if scope.ProviderID != c.ID || len(scope.IDs) == 0 {
		return out, errors.New("invalid Meraki scope")
	}
	want := map[string]bool{}
	for _, id := range scope.IDs {
		if !httpjson.Segment(id) || want[id] {
			return out, errors.New("invalid Meraki network scope")
		}
		want[id] = true
	}
	base := "/organizations/" + url.PathEscape(c.OrganizationID)
	raw, e := c.pages(ctx, base+"/devices?perPage=500", false)
	if e != nil {
		return out, e
	}
	devices, e := decode[device](raw)
	if e != nil {
		return out, e
	}
	// Join hardware to wireless status on BOTH serial and network, preserving
	// duplicate records for collision tombstones at the neutral publication layer.
	raw, e = c.pages(ctx, base+"/wireless/ssids/statuses/byDevice?perPage=500", true)
	if e != nil {
		return out, e
	}
	statuses, e := decode[status](raw)
	if e != nil {
		return out, e
	}

	conflicts := map[string]bool{}
	hardware := map[string]string{}
	labels := map[string]string{}
	for _, d := range devices {
		k := d.NetworkID + "\x00" + d.Serial
		m := network.MAC(d.MAC)
		if previous, ok := hardware[k]; ok && previous != m {
			conflicts[k] = true
		} else if !ok {
			hardware[k] = m
		}
	}
	for _, st := range statuses {
		k := st.Network.ID + "\x00" + st.Serial
		if previous, ok := labels[k]; ok && previous != st.Name {
			conflicts[k] = true
		} else if !ok {
			labels[k] = st.Name
		}
	}
	for _, id := range scope.IDs {
		out.Scopes = append(out.Scopes, domain.NetworkScopeResult{ScopeID: id, Status: domain.CapabilityFailed})
		prefix := "/networks/" + url.PathEscape(id)
		var n struct {
			ID       string   `json:"id"`
			Name     string   `json:"name"`
			Products []string `json:"productTypes"`
		}
		if _, e = c.HTTP.Get(ctx, c.HTTP.URL(prefix), &n); e != nil || n.ID != id || !network.Name(n.Name) || n.Products == nil {
			continue
		}
		hasAppliance, hasSwitch, hasWireless := false, false, false
		for _, p := range n.Products {
			hasAppliance = hasAppliance || p == "appliance"
			hasSwitch = hasSwitch || p == "switch"
			hasWireless = hasWireless || p == "wireless"
		}
		if !hasAppliance && !hasSwitch && !hasWireless {
			out.Scopes[len(out.Scopes)-1].Status = domain.CapabilityUnsupported
			continue
		}
		vlans, vlanStatus := c.vlans(ctx, prefix, id, hasAppliance)
		auth := []domain.Authenticator{}
		valid := true
		for _, d := range devices {
			if d.NetworkID != id || conflicts[d.NetworkID+"\x00"+d.Serial] {
				continue
			}
			if !httpjson.Segment(d.Serial) {
				valid = false
				break
			}
			a := domain.Authenticator{ID: c.ID + "/" + id + "/" + d.Serial, SiteID: id, Name: d.Name, HardwareMAC: network.MAC(d.MAC)}
			if d.ProductType == "switch" {
				ports, err := c.pages(ctx, "/devices/"+url.PathEscape(d.Serial)+"/switch/ports", false)
				if err != nil {
					valid = false
					break
				}
				for _, r := range ports {
					var p struct {
						ID string `json:"portId"`
					}
					if json.Unmarshal(r, &p) != nil || p.ID == "" {
						valid = false
						break
					}
					a.Ports = append(a.Ports, p.ID)
				}
			}
			matched := false
			for _, st := range statuses {
				if st.Serial == d.Serial && st.Network.ID == id {
					matched = true
					copy := a
					if network.Name(st.Name) {
						copy.Name = st.Name
					}
					for _, b := range st.BSS {
						if mac := network.MAC(b.BSSID); mac != "" {
							copy.MACs = append(copy.MACs, mac)
						}
					}
					auth = append(auth, copy)
				}
			}
			if !matched {
				auth = append(auth, a)
			}
		}
		if !valid {
			continue
		}
		now := time.Now()
		if c.Now != nil {
			now = c.Now()
		}
		out.Scopes[len(out.Scopes)-1] = domain.NetworkScopeResult{ScopeID: id, Status: domain.CapabilityAvailable, ObservedAt: domain.Unix(now), VLANStatus: vlanStatus, VLANObservedAt: domain.Unix(now)}
		out.Sites = append(out.Sites, domain.NetworkSite{ID: id, Name: n.Name})
		out.Authenticators = append(out.Authenticators, auth...)
		out.VLANs = append(out.VLANs, vlans...)
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	return out, nil
}

func (c *Client) vlans(ctx context.Context, prefix, id string, appliance bool) ([]domain.VLANMetadata, domain.CapabilityStatus) {
	path := prefix + "/vlanProfiles"
	if appliance {
		path = prefix + "/appliance/vlans"
	}
	rows, e := c.pages(ctx, path, false)
	if e != nil {
		return nil, domain.CapabilityFailed
	}
	out := []domain.VLANMetadata{}
	for _, r := range rows {
		if appliance {
			var v struct {
				ID   json.RawMessage `json:"id"`
				Name string          `json:"name"`
			}
			if json.Unmarshal(r, &v) != nil {
				return nil, domain.CapabilityFailed
			}
			var value string
			if json.Unmarshal(v.ID, &value) != nil {
				value = string(v.ID)
			}
			num, e := strconv.Atoi(value)
			if e != nil || !domain.ValidVLAN(num) || !network.Name(v.Name) {
				return nil, domain.CapabilityFailed
			}
			out = append(out, domain.VLANMetadata{SiteID: id, ID: num, Name: v.Name})
		} else {
			var profile struct {
				Names []struct {
					ID   string `json:"vlanId"`
					Name string `json:"name"`
				} `json:"vlanNames"`
			}
			if json.Unmarshal(r, &profile) != nil || profile.Names == nil {
				return nil, domain.CapabilityFailed
			}
			for _, v := range profile.Names {
				num, e := strconv.Atoi(v.ID)
				if e != nil || !domain.ValidVLAN(num) || !network.Name(v.Name) {
					return nil, domain.CapabilityFailed
				}
				out = append(out, domain.VLANMetadata{SiteID: id, ID: num, Name: v.Name})
			}
		}
	}
	return out, domain.CapabilityAvailable
}
