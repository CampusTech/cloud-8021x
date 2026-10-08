package policy

import (
	"encoding/json"
	"testing"
)

func TestNativeRESTPreservesAllValuesAndTypes(t *testing.T) {
	raw := []byte(`{"C8021X-Client":{"type":"string","value":["office"]},"C8021X-Source":{"type":"string","value":["2001:db8::1"]},"NAS-Port-Type":{"type":"integer","value":[19,15]},"Calling-Station-Id":{"type":"string","value":["a","b"]}}`)
	r, e := decodeNative(raw)
	if e != nil || len(r.NASPortTypes) != 2 || r.NASPortTypes[0] != "19" || len(r.CallingStations) != 2 {
		t.Fatal(r, e)
	}
	var attrs map[string]any
	_ = json.Unmarshal(raw, &attrs)
	attrs["C8021X-Client"] = map[string]any{"type": "string", "value": []string{"one", "two"}}
	bad, _ := json.Marshal(attrs)
	if _, e = decodeNative(bad); e == nil {
		t.Fatal("ambiguous native client")
	}
}
