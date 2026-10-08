// Package host owns fixed installed operating-system operations. The daemon has
// no root command execution interface.
package host

import (
	"errors"
	"fmt"
	"strings"
)

const MetadataRulesFile = "/etc/cloud-8021x/metadata.nft"

// MetadataRules is an atomic nft transaction. Google's internal DNS shares the
// metadata IPs, so only TCP/UDP destination 53 are exceptions. Address matching
// covers both documented aliases regardless of DNS, HTTPS and mapped IPv4.
func MetadataRules(uid int) ([]byte, error) {
	if uid <= 0 || uid > 1<<30 {
		return nil, errors.New("metadata isolation requires dedicated nonroot UID")
	}
	var b strings.Builder
	b.WriteString("add table inet cloud8021x_metadata\nflush table inet cloud8021x_metadata\ntable inet cloud8021x_metadata {\n chain output {\n  type filter hook output priority -10; policy accept;\n")
	for _, target := range []struct{ family, address string }{{"ip", "169.254.169.254"}, {"ip6", "fd20:ce::254"}, {"ip6", "::ffff:169.254.169.254"}} {
		for _, proto := range []string{"udp", "tcp"} {
			_, _ = fmt.Fprintf(&b, "  meta skuid %d %s daddr %s %s dport 53 accept\n", uid, target.family, target.address, proto)
		}
		_, _ = fmt.Fprintf(&b, "  meta skuid %d %s daddr %s reject\n", uid, target.family, target.address)
	}
	b.WriteString(" }\n}\n")
	return []byte(b.String()), nil
}
