package policy

import (
	"context"
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

func TestNativeHighCountDuplicatePortsStayAuthenticatedWithoutVLAN(t *testing.T) {
	for _, count := range []int{65, 190, 200, 201} {
		ports := make([]uint32, count)
		for i := range ports {
			ports[i] = 19
		}
		data, err := json.Marshal(map[string]any{
			"C8021X-Client": map[string]any{"type": "string", "value": []string{"office"}},
			"C8021X-Source": map[string]any{"type": "string", "value": []string{"192.0.2.1"}},
			"NAS-Port-Type": map[string]any{"type": "integer", "value": ports},
		})
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeNative(data)
		if count > 200 {
			if err == nil {
				t.Fatal("native attribute bound lost")
			}
			continue
		}
		if err != nil || len(decoded.NASPortTypes) != count {
			t.Fatalf("count %d: %v", count, err)
		}
		service, request, _ := setup(t)
		request.NASPortTypes = decoded.NASPortTypes
		result, err := service.Decide(context.Background(), request)
		if err != nil || result.Decision.VLAN != nil || result.Class == "" {
			t.Fatalf("count %d failed no-VLAN authentication: %+v %v", count, result, err)
		}
	}
}
