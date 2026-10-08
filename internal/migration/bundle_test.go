package migration

import (
	"encoding/json"
	"strings"
	"testing"
)

func minimalBundle() Bundle {
	return Bundle{Version: 1, Node: "radius-primary", Policy: json.RawMessage(`{"version":2,"updated_at":1791453600.123456789,"identities":{"ambiguous":null},"certificates":{},"hardware_serials":{}}`), ClassKeySHA256: strings.Repeat("a", 64), FingerprintEnforced: true, Usage: json.RawMessage(`{"version":1,"tracker":{"version":1,"sessions":[]},"through":null,"pending":[],"uncertain":false,"seeded":false,"preview_id":null}`), SQL: LegacySQL{Status: "absent"}}
}
func TestWholeBundlePreservesOriginalDataAndRejectsLateInvalidComponent(t *testing.T) {
	b := minimalBundle()
	raw, _ := json.Marshal(b)
	got, e := DecodeBundle(raw)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(got.Policy), "1791453600.123456789") || !strings.Contains(string(got.Policy), `"ambiguous":null`) {
		t.Fatal("original age or ambiguity rewritten")
	}
	b.Certificates = json.RawMessage(`{"version":1,"source":"https://fleet.example.invalid","trust":null,"hosts":{},"commands":[{"uuid":"x","created_at":1,"hosts":{"missing":[1,1,null]}}]}`)
	raw, _ = json.Marshal(b)
	if _, e = DecodeBundle(raw); e == nil {
		t.Fatal("orphan command passed full validation")
	}
	b = minimalBundle()
	b.SQL.Status = "unavailable"
	raw, _ = json.Marshal(b)
	if _, e = DecodeBundle(raw); e == nil {
		t.Fatal("unknown old database treated as empty")
	}
	b = minimalBundle()
	b.FingerprintEnforced = false
	b.ClassKeySHA256 = ""
	raw, _ = json.Marshal(b)
	if _, e = DecodeBundle(raw); e == nil {
		t.Fatal("missing Class key binding accepted")
	}
}
