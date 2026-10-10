package policy

import (
	"errors"
	"net/netip"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

type Client struct {
	ID               string
	LocationID       domain.LocationID
	CIDRs            []string
	Medium           domain.NetworkMedium
	SignalingProfile string
}
type mappedClient struct {
	context domain.TrustedNetworkContext
	ranges  []netip.Prefix
}
type TrustMap struct{ clients map[string]mappedClient }

func NewTrustMap(clients []Client) (*TrustMap, error) {
	m := &TrustMap{clients: map[string]mappedClient{}}
	var ranges []netip.Prefix
	for _, c := range clients {
		if c.ID == "" || c.LocationID == "" || len(c.CIDRs) == 0 || (c.Medium != domain.WiFi && c.Medium != domain.Wired) {
			return nil, errors.New("invalid trusted RADIUS client")
		}
		if _, ok := m.clients[c.ID]; ok {
			return nil, errors.New("duplicate trusted client")
		}
		mapped := mappedClient{context: domain.TrustedNetworkContext{ClientID: c.ID, LocationID: c.LocationID, Medium: c.Medium, SignalingProfile: c.SignalingProfile}}
		for _, cidr := range c.CIDRs {
			p, err := netip.ParsePrefix(cidr)
			if err != nil || p.Bits() == 0 || p != p.Masked() || p.Addr().Zone() != "" || p.Addr().Is4In6() {
				return nil, errors.New("noncanonical or unbounded trusted source CIDR")
			}
			for _, other := range ranges {
				if p.Overlaps(other) {
					return nil, errors.New("trusted source CIDRs overlap")
				}
			}
			ranges = append(ranges, p)
			mapped.ranges = append(mapped.ranges, p)
		}
		m.clients[c.ID] = mapped
	}
	return m, nil
}

// The caller supplies the FreeRADIUS-authenticated configured client ID and actual
// transport source. Packet NAS fields are deliberately not arguments to this API.
func (m *TrustMap) AuthenticatedClient(clientID, source string) (domain.TrustedNetworkContext, error) {
	client, ok := m.clients[clientID]
	if !ok {
		return domain.TrustedNetworkContext{}, errors.New("unknown authenticated RADIUS client")
	}
	ip, err := netip.ParseAddr(source)
	if err != nil || ip.Zone() != "" || ip.Is4In6() {
		return domain.TrustedNetworkContext{}, errors.New("invalid authenticated transport source")
	}
	for _, cidr := range client.ranges {
		if cidr.Contains(ip) {
			ctx := client.context
			ctx.SourceIP = ip.String()
			return ctx, nil
		}
	}
	return domain.TrustedNetworkContext{}, errors.New("source does not match authenticated RADIUS client")
}
