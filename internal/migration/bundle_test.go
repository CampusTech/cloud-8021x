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

func TestReceiptTimePreservesExactDecimalNanoseconds(t *testing.T) {
	for _, raw := range []string{"1791453600.123456789", "1791453600.999999999", "1.791453600123456789e9"} {
		got, e := ReceiptTime([]byte(raw))
		if e != nil {
			t.Fatal(e)
		}
		want := 123456789
		if raw == "1791453600.999999999" {
			want = 999999999
		}
		if got.Unix() != 1791453600 || got.Nanosecond() != want {
			t.Fatalf("original receipt rounded: %s -> %s", raw, got)
		}
	}
}

func TestLegacyReadinessRejectsUntypedRowsAndPreservesOriginalReport(t *testing.T) {
	b := minimalBundle()
	b.Readiness = json.RawMessage(`{"ready":true,"ready_count":1,"generated_at":1791453600.123456789,"max_age":86400,"total":1,"hosts":[{"id":1,"uuid":"uuid","reason":"ready","certificate_reason":"ready","locations":{"office":{"reason":"ready","vlan":120}}}],"updated_at":1791453600.123456789,"policy_enforced":true}`)
	raw, _ := json.Marshal(b)
	if _, e := DecodeBundle(raw); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{`{"updated_at":1,"hosts":"untyped"}`, strings.Replace(string(b.Readiness), `"ready_count":1`, `"ready_count":2`, 1), strings.Replace(string(b.Readiness), `"vlan":120`, `"vlan":5000`, 1)} {
		b.Readiness = json.RawMessage(bad)
		raw, _ = json.Marshal(b)
		if _, e := DecodeBundle(raw); e == nil {
			t.Fatal("malformed explanatory report accepted", bad)
		}
	}
}
