package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRemoteSeedSeparatesWindowsWorkFromOriginalAppleAuthority(t *testing.T) {
	at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	pin := strings.Repeat("a", 64)
	c, err := makeRemoteContract(remoteSeedSpec{ApplicationSHA256: pin, FleetAuthorization: "Bearer synthetic-private-test-token", IntakeHost: "otlp.us5.datadoghq.com", IntakeAPIKey: "synthetic-private-test-key"}, at)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Fleet.Commands) != 1 || len(c.Fleet.Hosts) != 2 || c.Fleet.Hosts[0].UUID != syntheticDevice || c.Fleet.Hosts[1].UUID != syntheticWindows || c.Peers["10.203.11.21"]["phase"] != "passive" || c.Peers["10.203.11.31"]["phase"] != "active" {
		t.Fatal("remote scope or initial permission changed")
	}
	raw, _ := json.Marshal(map[string]any{"contract": c})
	green, err := approvedGreenHosts(raw, pin)
	if err != nil || len(green) != 1 || green[syntheticWindows].Platform != "windows" {
		t.Fatal("separate approved remote enrollment unavailable", err)
	}
	if _, ok := green[syntheticDevice]; ok {
		t.Fatal("original Apple work newly collectible")
	}
	for _, change := range []func(){func() { c.Fleet.Hosts[1].UUID = syntheticDevice }, func() { c.Fleet.Hosts[1].Serial = "unreviewed-display" }, func() { c.ApplicationSHA256 = strings.Repeat("b", 64) }} {
		saved := *c
		saved.Fleet.Hosts = append([]remoteHost{}, c.Fleet.Hosts...)
		change()
		bad, _ := json.Marshal(map[string]any{"contract": c})
		if _, e := approvedGreenHosts(bad, pin); e == nil {
			t.Fatal("changed approved seed accepted")
		}
		*c = saved
	}
}
