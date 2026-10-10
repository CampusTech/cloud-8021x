package main

import (
	"strings"
	"testing"
	"time"
)

func TestNASExpectationsBindActualClassToIndependentClientFingerprint(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	key, token := actualClassForPureTest(t, now)
	p := pureNASPlan()
	p.Materials["class-key"] = digestBytes(key)
	expected, e := deriveNASExpectations(p, token, key, now, now)
	if e != nil {
		t.Fatal(e)
	}
	if len(expected.Events) != 3 || len(expected.Intervals) != 2 || expected.Upload != 1600 || expected.Download != 2900 {
		t.Fatal("independent expected accounting deltas changed")
	}
	for _, bad := range []string{"client-fingerprint", "class-key-pin", "station", "expiry"} {
		t.Run(bad, func(t *testing.T) {
			plan := pureNASPlan()
			plan.Materials["class-key"] = digestBytes(key)
			received := now
			switch bad {
			case "client-fingerprint":
				plan.ClientLeafSHA256 = strings.Repeat("b", 64)
			case "class-key-pin":
				plan.Materials["class-key"] = strings.Repeat("f", 64)
			case "station":
				plan.Station = "00:11:22:33:44:55"
			case "expiry":
				received = now.Add(31 * 24 * time.Hour)
			}
			if _, e := deriveNASExpectations(plan, token, key, received, now); e == nil {
				t.Fatal("server-observed identity replaced independent NAS context")
			}
		})
	}
}
