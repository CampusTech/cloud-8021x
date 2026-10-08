package migration

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCurrentExportRetainsTypedProviderAndSourceBindings(t *testing.T) {
	n := NodeState{Version: 1, Node: "radius-primary", ClassKeySHA256: strings.Repeat("a", 64), Inventory: UnavailableInventory(), ProviderCaches: map[string]json.RawMessage{}}
	for _, bad := range []json.RawMessage{json.RawMessage(`{"Key":"short","Batch":{}}`), json.RawMessage(`{"Key":"` + strings.Repeat("a", 64) + `","Batch":{"ProviderID":"foreign"}}`)} {
		n.ProviderCaches["p"] = bad
		raw, _ := json.Marshal(n)
		if _, e := DecodeNodeState(raw); e == nil {
			t.Fatal("unknown provider binding accepted")
		}
	}
	n.ProviderCaches = map[string]json.RawMessage{}
	for _, candidates := range []string{`[{"ProviderID":"p","SiteID":"s","ObservedAt":1791453600,"CIDRs":["192.0.2.1/24"]}]`, `[{"ProviderID":"","SiteID":"s","ObservedAt":1791453600,"CIDRs":[]}]`} {
		n.Discovery = json.RawMessage(candidates)
		raw, _ := json.Marshal(n)
		if _, e := DecodeNodeState(raw); e == nil {
			t.Fatal("invalid retained discovery accepted")
		}
	}
	n.Discovery = nil
	n.ProtectedSources = json.RawMessage(`{"ConfigSHA256":"short","Candidates":[]}`)
	raw, _ := json.Marshal(n)
	if _, e := DecodeNodeState(raw); e == nil {
		t.Fatal("unknown protected config accepted")
	}
}
