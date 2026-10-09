package main

import (
	"fmt"
	"strings"
)

type endpoint struct{ Name, Address string }

func endpoints(p plan) []endpoint {
	var out []endpoint
	for _, n := range p.Nodes {
		out = append(out, endpoint{n.Namespace, n.Address})
	}
	return append(out, endpoint{"c11-api", "10.203.11.10"}, endpoint{"c11-pg", "10.203.11.11"}, endpoint{"c11-nas", "10.203.11.40"})
}
func bridgeRules(p plan) (string, error) {
	if e := p.validate(); e != nil {
		return "", e
	}
	var b strings.Builder
	b.WriteString("table bridge task11_platform {\n chain forward { type filter hook forward priority 0; policy drop;\n")
	peers := map[string]string{}
	for _, e := range endpoints(p) {
		peers[e.Address] = e.Name + "-h"
	}
	for _, e := range endpoints(p) {
		fmt.Fprintf(&b, "  iifname %q ether type ip ip saddr != %s drop\n", e.Name+"-h", e.Address)
		for _, d := range endpoints(p) {
			if d.Address != e.Address {
				fmt.Fprintf(&b, "  iifname %q oifname %q ether type arp arp saddr ip %s arp daddr ip %s accept\n", e.Name+"-h", d.Name+"-h", e.Address, d.Address)
			}
		}
	}
	for _, f := range p.Flows {
		fmt.Fprintf(&b, "  iifname %q ip saddr %s oifname %q ip daddr %s %s dport %d ct state new,established accept\n", peers[f.Source], f.Source, peers[f.Destination], f.Destination, f.Protocol, f.Port)
		fmt.Fprintf(&b, "  iifname %q ip saddr %s oifname %q ip daddr %s %s sport %d ct state established accept\n", peers[f.Destination], f.Destination, peers[f.Source], f.Source, f.Protocol, f.Port)
	}
	b.WriteString(" }\n}\ntable inet task11_platform {\n chain input { type filter hook input priority 0; policy drop; iifname lo accept; }\n chain output { type filter hook output priority 0; policy drop; oifname lo accept; }\n chain forward { type filter hook forward priority 0; policy drop; }\n}\n")
	return b.String(), nil
}
func namespaceRules(p plan, address string) string {
	var b strings.Builder
	b.WriteString("table inet task11_node {\n chain input { type filter hook input priority 0; policy drop; iifname lo accept;\n")
	for _, f := range p.Flows {
		if f.Destination == address {
			fmt.Fprintf(&b, " ip saddr %s ip daddr %s %s dport %d ct state new,established accept\n", f.Source, address, f.Protocol, f.Port)
		}
		if f.Source == address {
			fmt.Fprintf(&b, " ip saddr %s ip daddr %s %s sport %d ct state established accept\n", f.Destination, address, f.Protocol, f.Port)
		}
	}
	b.WriteString(" }\n chain output { type filter hook output priority 0; policy drop; oifname lo accept;\n")
	for _, f := range p.Flows {
		if f.Source == address {
			fmt.Fprintf(&b, " ip saddr %s ip daddr %s %s dport %d ct state new,established accept\n", address, f.Destination, f.Protocol, f.Port)
		}
		if f.Destination == address {
			fmt.Fprintf(&b, " ip saddr %s ip daddr %s %s sport %d ct state established accept\n", address, f.Source, f.Protocol, f.Port)
		}
	}
	b.WriteString(" }\n chain forward { type filter hook forward priority 0; policy drop; }\n}\n")
	return b.String()
}
