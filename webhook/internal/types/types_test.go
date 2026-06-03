package types

import (
	"encoding/json"
	"testing"
)

func TestParseAttestationSerial(t *testing.T) {
	body := `{"timestamp":"2026-06-02T00:00:00Z","provisionerName":"wifi-acme","attestationData":{"permanentIdentifier":"FRAGAACPA74412000D"}}`
	var req RequestBody
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.AttestationData == nil || req.AttestationData.PermanentIdentifier != "FRAGAACPA74412000D" {
		t.Fatalf("got %#v", req.AttestationData)
	}
}

func TestResponseAllowJSON(t *testing.T) {
	b, _ := json.Marshal(ResponseBody{Allow: true})
	if string(b) != `{"allow":true}` {
		t.Fatalf("got %s", b)
	}
}
