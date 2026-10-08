package migration

import (
	"bytes"
	"math"
	"strings"
	"testing"
)

func TestLegacyUsageRoundTripPreservesPrecisionTerminalAndUncertainty(t *testing.T) {
	input := `{"version":1,"tracker":{"version":1,"sessions":[{"key":["192.0.2.1","10.0.0.1","aabbccddeeff","session"],"duration":42,"upload":18446744073709551615,"download":3,"stopped":true,"display":{"host":"radius-primary"},"identity":null,"last_seen":1728000000.125}]},"through":1728000001.25,"pending":[{"event":"Acct-Usage","service":"radius-usage","usage_id":"` + strings.Repeat("a", 64) + `","hostname":"radius-primary","timestamp":1728000001.125,"input_bytes":12,"upload_delta_bytes":12,"output_bytes":4,"download_delta_bytes":4,"counter_quality":"full_64bit","preview_id":null}],"uncertain":true,"seeded":true,"preview_id":null}`
	checkpoint, e := DecodeUsage([]byte(input), []string{"radius-primary", "radius-secondary"})
	if e != nil {
		t.Fatal(e)
	}
	s := checkpoint.Tracker.Sessions[0]
	if s.Upload != math.MaxUint64 || s.CounterBits != 64 || s.FormatMarked || !s.Stopped {
		t.Fatalf("lossy legacy state: %+v", s)
	}
	output, e := checkpoint.Encode()
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(output, []byte("18446744073709551615")) || !bytes.Contains(output, []byte("1728000000.125")) {
		t.Fatal("precision lost", string(output))
	}
	again, e := DecodeUsage(output, []string{"radius-primary", "radius-secondary"})
	if e != nil || !again.Uncertain || len(again.Pending) != 1 {
		t.Fatal("uncertain batch not retained", e)
	}
}
func TestLegacyUsageRejectsPartialMalformedBeforeImport(t *testing.T) {
	base := `{"version":1,"tracker":{"version":1,"sessions":[]},"through":null,"pending":[],"uncertain":false,"seeded":false,"preview_id":null}`
	for _, input := range []string{strings.Replace(base, `"uncertain":false`, `"uncertain":true`, 1), strings.Replace(base, `"sessions":[]`, `"sessions":null`, 1), strings.Replace(base, `"seeded":false`, `"seeded":false,"seeded":true`, 1), strings.Replace(base, `"version":1`, `"version":2`, 1), strings.Replace(base, `,"seeded":false`, "", 1)} {
		if _, e := DecodeUsage([]byte(input), []string{"radius-primary"}); e == nil {
			t.Fatal("accepted malformed checkpoint", input)
		}
	}
}
