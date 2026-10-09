package main

import (
	"strings"
	"testing"
)

func TestRenderedNetworkCannotAdmitSpoofedSourceOrUplink(t *testing.T) {
	p := validPlan()
	rules, e := bridgeRules(p)
	if e != nil {
		t.Fatal(e)
	}
	for _, n := range p.Nodes {
		if !strings.Contains(rules, "iifname \""+n.Namespace+"-h\" ip saddr "+n.Address) {
			t.Fatal("source interface not bound to physical IP")
		}
	}
	if !strings.Contains(rules, "policy drop") || strings.Contains(rules, "masquerade") || strings.Contains(rules, "0.0.0.0/0") {
		t.Fatal("network isolation missing")
	}
	p.Flows = append(p.Flows, flow{"10.203.11.21", "8.8.8.8", "udp", 53})
	if _, e = bridgeRules(p); e == nil {
		t.Fatal("internet flow accepted")
	}
}
