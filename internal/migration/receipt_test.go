package migration

import "testing"

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
