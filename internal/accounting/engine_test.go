package accounting

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
)

func raw(status string, duration, up, down string) Raw {
	return Raw{SourceIP: "192.0.2.1", NASIP: Attribute{"192.0.2.2", 1}, Station: Attribute{"aa:bb:cc:dd:ee:ff", 1}, Session: Attribute{"s", 1}, Status: Attribute{status, 1}, Duration: Attribute{duration, 1}, Input: Attribute{up, 1}, Output: Attribute{down, 1}, Location: "site", Client: "client", Host: "host", ReplayID: "replay", Received: time.Unix(1800000000, 0)}
}
func event(t *testing.T, r Raw) Event {
	t.Helper()
	e, err := Normalize(r, nil, binding.MaxAge)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func TestExactNativeCounters(t *testing.T) {
	r := raw("Interim-Update", "10", "4294967295", "1")
	r.InputHigh = Attribute{"4294967295", 1}
	e := event(t, r)
	if e.Upload != math.MaxUint64 || e.Download != 1 || e.Bits != 64 {
		t.Fatalf("not exact: %+v", e)
	}
	for _, a := range []Attribute{{"x", 1}, {"-1", 1}, {"4294967296", 1}, {"0", 2}, {"oops", 0}} {
		r.InputHigh = a
		if _, err := Normalize(r, nil, binding.MaxAge); err == nil {
			t.Fatal("bad high word accepted", a)
		}
	}
	r.InputHigh = Attribute{}
	r.Input.Count = 0
	if _, err := Normalize(r, nil, binding.MaxAge); err == nil {
		t.Fatal("missing low accepted")
	}
	r.Status = Attribute{"Start", 1}
	if e := event(t, r); e.Upload != 0 || e.Duration != 0 {
		t.Fatal("Start not zero")
	}
}
func TestBaselineResetReorderPrecisionAndStop(t *testing.T) {
	s := State{}
	e := event(t, raw("Interim-Update", "10", "100", "200"))
	s, u, _ := Apply(s, e)
	if u != nil {
		t.Fatal("invented initial bytes")
	}
	e = event(t, raw("Interim-Update", "20", "150", "300"))
	s, u, _ = Apply(s, e)
	if u == nil || u.Upload != 50 || u.Download != 100 {
		t.Fatal(u)
	}
	for _, r := range []Raw{raw("Start", "0", "0", "0"), raw("Interim-Update", "19", "1000", "1000"), raw("Interim-Update", "20", "149", "300")} {
		next, u, _ := Apply(s, event(t, r))
		if u != nil || next.Upload != 150 {
			t.Fatal("late/reset same duration changed state")
		}
	}
	s, u, reason := Apply(s, event(t, raw("Interim-Update", "30", "1", "2")))
	if u != nil || reason != "counter_reset" {
		t.Fatal(reason)
	}
	e = event(t, raw("Interim-Update", "40", "10", "20"))
	e.Bits = 32
	s, u, reason = Apply(s, e)
	if u != nil || reason != "precision_change" {
		t.Fatal(reason)
	}
	e = event(t, raw("Stop", "50", "20", "30"))
	e.Bits = 32
	s, u, _ = Apply(s, e)
	if u == nil || !s.Stopped {
		t.Fatal("stop not credited")
	}
	_, u, _ = Apply(s, e)
	if u != nil {
		t.Fatal("stop duplicated")
	}
}
func TestLegacyUnmarkedLowWordNeverDowngradesNative(t *testing.T) {
	s := State{Initialized: true, Bits: 64, Marked: true, Upload: 1 << 40, Duration: 10}
	e := event(t, raw("Stop", "20", "1", "1"))
	e.Bits = 32
	e.Marked = false
	next, u, _ := Apply(s, e)
	if u != nil || next.Stopped || next.Upload != s.Upload {
		t.Fatal("legacy low-word contaminated session")
	}
}
func TestIdentityDedupeAndReceipt(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	r := raw("Interim-Update", "10", "100", "200")
	r.CalledStation = "ap:ssid"
	r.NASPort = "2"
	v := 42
	token, err := binding.Issue(key, binding.Attribution{DeviceID: "d", Fingerprint: strings.Repeat("ab", 32), VLAN: &v}, r.Location, r.Station.Value, r.Received.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	r.Class = Attribute{token, 1}
	e, err := Normalize(r, key, binding.MaxAge)
	if err != nil || e.Identity == nil || *e.Identity.VLAN != 42 {
		t.Fatal("attribution failed", err)
	}
	if e.CalledStation != r.CalledStation || e.NASPort != r.NASPort {
		t.Fatal("display context lost")
	}
	r.Host = "other"
	r.ReplayID = "retry"
	r.Received = r.Received.Add(time.Minute)
	retry, err := Normalize(r, key, binding.MaxAge)
	if err != nil || e.ID != retry.ID {
		t.Fatal("retry not semantic")
	}
	r.Class.Count = 2
	e, err = Normalize(r, key, binding.MaxAge)
	if err != nil || e.Identity != nil || e.AttributionIssue == "" {
		t.Fatal("invalid binding not unattributed")
	}
	r.Session.Count = 2
	if _, err := Normalize(r, key, binding.MaxAge); err == nil {
		t.Fatal("ambiguous session accepted")
	}
}
func TestUsageIDLegacyCoordinates(t *testing.T) {
	s := State{}
	s, _, _ = Apply(s, event(t, raw("Start", "0", "0", "0")))
	e := event(t, raw("Interim-Update", "10", "100", "200"))
	_, u, _ := Apply(s, e)
	if u.ID != "43399daaa58e35ff9e98d95c5a6e0e3da8e986df75703405ae1a40722b679bcf" {
		t.Fatal("legacy coordinate digest changed", u.ID)
	}
	e.Received = e.Received.Add(time.Hour)
	_, v, _ := Apply(s, e)
	if u.ID != v.ID {
		t.Fatal("receipt changed usage identity")
	}
}

func TestUnknownNetworkIdentityCannotCreateSharedSession(t *testing.T) {
	for _, v := range []string{"unknown", "N/A", "192.0.2.1/24", "127.1", ""} {
		r := raw("Start", "0", "0", "0")
		r.SourceIP = v
		if _, err := CanonicalKey(r); err == nil {
			t.Fatal("invalid source accepted", v)
		}
		r = raw("Start", "0", "0", "0")
		r.NASIP.Value = v
		if _, err := CanonicalKey(r); err == nil {
			t.Fatal("invalid NAS accepted", v)
		}
	}
}

func TestUsageIDLegacyStringEscaping(t *testing.T) {
	// Fixed digests from radius_usage.py's json.dumps([key, previous, current],
	// separators=(",", ":")), with Python's default ensure_ascii=True.
	cases := []struct{ name, session, want string }{
		{"unicode", "東京", "3c5cc1b88a66e81ad7729b8debb69ea698b36b3897cb14a9f6954b1eafc10dbc"},
		{"less-than", "a<b", "e00c0002a6ad09943f44bf9d83bcc827c92144098deee0fc2a0dd6b83f47df26"},
		{"html", "a>&b", "459e2cd37b9503995ee3bf8c5b83d83e06192a4cc7ef01a0fb3777a60b26c243"},
		{"astral", "session-😀", "770468394cd30962817c2d07513e43ff95add05aecb6cdea1ce3e53015baab8d"},
		{"quotes-and-slashes", "a\"b\\c/d", "8734d0755c06267ea334ac17f92808b00e9b97031c65c58f0dff57bd043457fc"},
		{"short-controls", "a\b\f\n\r\tb", "a62b27c0416a160bdb87d9e93effb1ea31af094942345c8a3dcbf56aaa234f3d"},
		{"escaped-controls-and-del", "a\x01\x1f\x7fb", "0c47f9dbcdb13d90d2f012ff7d0d014cc7e478b54aaed0c858f733cbeb96efb9"},
		{"line-separators", "a\u2028\u2029b", "24f0533f1656628333d06aa026d36ae97654031b927efa9f15b475e4a848cb26"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := raw("Start", "0", "0", "0")
			start.Session.Value = tc.session
			state, _, _ := Apply(State{}, event(t, start))
			interim := raw("Interim-Update", "10", "100", "200")
			interim.Session.Value = tc.session
			_, interval, _ := Apply(state, event(t, interim))
			if interval == nil || interval.ID != tc.want {
				t.Fatalf("legacy usage ID mismatch: got %+v, want %s", interval, tc.want)
			}
		})
	}
}

func TestIntervalRetainsOriginalProducerContext(t *testing.T) {
	e := Event{Key: [4]string{"192.0.2.1", "192.0.2.2", "aabbccddeeff", "session"}, Status: "Interim-Update", Duration: 20, Upload: 200, Download: 300, Bits: 64, Marked: true, Received: time.Now(), Host: "origin", Location: "nyc", CalledStation: "aa:bb:cc:dd:ee:ff:ssid", NASPort: "19"}
	s := State{Initialized: true, Duration: 10, Upload: 100, Download: 100, Bits: 64, Marked: true, LastSeen: e.Received.Add(-time.Minute)}
	_, interval, _ := Apply(s, e)
	if interval == nil || interval.Host != e.Host || interval.Location != e.Location || interval.CalledStation != e.CalledStation || interval.NASPort != e.NASPort {
		t.Fatalf("lost producer context: %+v", interval)
	}
	id := interval.ID
	e.Host = "another"
	e.Location = "other"
	_, other, _ := Apply(s, e)
	if other == nil || other.ID != id {
		t.Fatal("display context changed semantic usage ID")
	}
}

func TestTerminationCauseIsDisplayOnly(t *testing.T) {
	r := raw("Stop", "10", "100", "200")
	baseline := event(t, r)
	for _, tc := range []struct {
		attr Attribute
		want string
	}{
		{Attribute{}, "N/A"}, {Attribute{"User-Request", 1}, "User-Request"},
		{Attribute{"Lost-Carrier", 1}, "Lost-Carrier"}, {Attribute{"1", 1}, "User-Request"},
		{Attribute{"User-Request", 2}, "N/A"}, {Attribute{"9999", 1}, "N/A"}, {Attribute{"secret arbitrary value", 1}, "N/A"},
	} {
		r.TerminateCause = tc.attr
		got := event(t, r)
		if got.TerminateCause != tc.want || got.ID != baseline.ID || got.Upload != baseline.Upload || got.Download != baseline.Download || got.Identity != nil {
			t.Fatalf("changed semantic event: %+v", got)
		}
	}
}
