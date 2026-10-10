package migration

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

func TestCurrentExportRetainsTypedProviderAndSourceBindings(t *testing.T) {
	n := NodeState{Version: 1, Node: "radius-primary", ClassKeySHA256: strings.Repeat("a", 64), Inventory: json.RawMessage(`{"version":2,"updated_at":0,"identities":{},"certificates":{},"hardware_serials":{}}`), ProviderCaches: map[string]json.RawMessage{}}
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

func TestCurrentExportPositiveOriginalProviderAndSourceRoundTrip(t *testing.T) {
	at := domain.Timestamp(1791453600.125)
	batch := domain.NetworkSnapshot{ProviderID: "p", Scope: domain.InventoryScope{ProviderID: "p", IDs: []string{"s"}}, Scopes: []domain.NetworkScopeResult{{ScopeID: "s", Status: domain.CapabilityAvailable, ObservedAt: at, VLANStatus: domain.CapabilityAvailable, VLANObservedAt: at}}, VLANs: []domain.VLANMetadata{{SiteID: "s", ID: 120, Name: "Staff"}}}
	cache, _ := json.Marshal(struct {
		Key   string
		Batch domain.NetworkSnapshot
	}{strings.Repeat("b", 64), batch})
	candidates := []domain.SourceCandidate{{ProviderID: "p", SiteID: "s", CIDRs: []string{"192.0.2.0/24"}, ObservedAt: at}}
	discovery, _ := json.Marshal(candidates)
	protected, _ := json.Marshal(struct {
		ConfigSHA256 string
		Candidates   []domain.SourceCandidate
	}{strings.Repeat("c", 64), candidates})
	original := NodeState{Version: 1, Node: "radius-primary", ClassKeySHA256: strings.Repeat("a", 64), Inventory: json.RawMessage(`{"version":2,"updated_at":0,"identities":{},"certificates":{},"hardware_serials":{}}`), ProviderCaches: map[string]json.RawMessage{"p": cache}, Discovery: discovery, ProtectedSources: protected}
	raw, _ := json.Marshal(original)
	decoded, e := DecodeNodeState(raw)
	if e != nil || !reflect.DeepEqual(decoded, original) {
		t.Fatalf("original evidence changed: %v %#v", e, decoded)
	}
	again, _ := json.Marshal(decoded)
	if string(again) != string(raw) {
		t.Fatal("roundtrip changed original times/scope/cache binding")
	}
}
