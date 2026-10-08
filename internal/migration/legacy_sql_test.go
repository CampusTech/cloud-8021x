package migration

import (
	"encoding/json"
	"math"
	"testing"
)

func TestSQLCaptureRetainsNaiveDatabaseTimeWithOriginalZoneAndExactCounters(t *testing.T) {
	at := "2026-10-08 12:34:56.123456"
	counter := uint64(math.MaxUint64)
	s := LegacySQL{Status: "exported", SessionTimeZone: "SYSTEM", SystemTimeZone: "EDT", ServerVersion: "11.4", Rows: []LegacySQLRow{{ID: 1, UniqueID: "id", SessionID: "session", NASAddress: "192.0.2.1", Start: &at, Input: &counter}}}
	if e := validateSQL(s); e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(s)
	if e != nil {
		t.Fatal(e)
	}
	var got LegacySQL
	if e = json.Unmarshal(raw, &got); e != nil {
		t.Fatal(e)
	}
	if *got.Rows[0].Input != math.MaxUint64 || *got.Rows[0].Start != at || got.Rows[0].Stop != nil {
		t.Fatal("lost original SQL values")
	}
	s.SystemTimeZone = ""
	if e = validateSQL(s); e == nil {
		t.Fatal("naive time accepted without original timezone evidence")
	}
}
