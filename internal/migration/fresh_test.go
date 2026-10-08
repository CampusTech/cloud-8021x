package migration

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFreshBundleNeverFabricatesObservation(t *testing.T) {
	raw, e := FreshBundle("radius-primary", strings.Repeat("a", 64), strings.Repeat("b", 64))
	if e != nil {
		t.Fatal(e)
	}
	b, e := DecodeBundle(raw)
	if e != nil || b.FreshAbsenceSHA256 == "" {
		t.Fatal(e)
	}
	b.Policy = json.RawMessage(`{"version":2,"updated_at":1791453600,"identities":{},"certificates":{},"hardware_serials":{}}`)
	raw, _ = json.Marshal(b)
	if _, e = DecodeBundle(raw); e == nil {
		t.Fatal("fresh provenance contains fabricated observation")
	}
}
