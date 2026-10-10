package network

import (
	"net/netip"
)

// PublicIPv4 excludes special-use ranges, including documentation, CGNAT and
// benchmarking ranges; none can be authenticated public RADIUS egress evidence.
func PublicIPv4(a netip.Addr) bool {
	if !a.Is4() || !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	for _, s := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4"} {
		if netip.MustParsePrefix(s).Contains(a) {
			return false
		}
	}
	return true
}
