package main

import (
	"encoding/json"
	"testing"
)

func TestNASActionUsesSolePrivateRequestBeforeMaterialOrEffects(t *testing.T) {
	input := pureNASInput(t)
	// Obtain valid exact shared request bytes for the fixed native action.
	r, e := decodeNASInputCore(encodePureNASInput(t, input))
	if e != nil {
		t.Fatal(e)
	}
	r.Request.Action = "nas-native"
	input.RequestBytes = mustJSON(t, r.Request)
	input.RequestSHA256 = digestBytes(input.RequestBytes)
	decoded, e := decodeNASAction("nas-native", encodePureNASInput(t, input))
	if e != nil || decoded.Request.Action != "nas-native" || decoded.Plan.Scenario.Case != "native-accounting" {
		t.Fatal("sole fixed nas private action admission absent", e)
	}
	for _, action := range []string{"nas-outage", "/bin/sh", "nas-native extra", "admit"} {
		if _, e = decodeNASAction(action, encodePureNASInput(t, input)); e == nil {
			t.Fatal("argv/private action mismatch or generic executor accepted")
		}
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
