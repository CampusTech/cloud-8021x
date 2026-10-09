package main

import (
	"strings"
	"testing"
)

func TestKernelParsersRefuseUnknownAndDecodeIPv6(t *testing.T) {
	raw := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n 0: 00000000000000000000000000000000:0714 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 123 1\n"
	s, e := parseSockets([]byte(raw), "tcp6")
	if e != nil || len(s) != 1 || s[0].Local != "[::]:1812" || s[0].Inode != 123 {
		t.Fatal("real proc socket format not decoded", s, e)
	}
	if _, e = parseSockets([]byte(strings.Replace(raw, "0714", "ZZZZ", 1)), "tcp6"); e == nil {
		t.Fatal("unknown port accepted")
	}
	if _, e = parseSockets([]byte("not proc format"), "tcp"); e == nil {
		t.Fatal("unknown socket table accepted")
	}
	start, parent, e := parseStat([]byte("1 (systemd (pid1)) S 0 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 321 0"))
	if e != nil || start != 321 || parent != 0 {
		t.Fatal("stat command parentheses broke start identity", start, parent, e)
	}
	if _, _, e = parseStat([]byte("1 (?) S 0")); e == nil {
		t.Fatal("truncated process identity accepted")
	}
}
func TestTimerPropertiesDoNotInventServiceProcesses(t *testing.T) {
	raw := "Id=cloud-8021x-renew.timer\nLoadState=loaded\nActiveState=active\nSubState=waiting\nUnitFileState=enabled\nConditionResult=yes\nFragmentPath=/etc/systemd/system/cloud-8021x-renew.timer\nDropInPaths=\nTriggers=cloud-8021x-renew.service\n"
	u, e := parseUnit(raw, "cloud-8021x-renew.timer")
	if e != nil || u.SubState != "waiting" {
		t.Fatal("actual timer interface unavailable", u, e)
	}
	if _, e = parseUnit(raw+"MainPID=42\n", "cloud-8021x-renew.timer"); e == nil {
		t.Fatal("unknown timer property accepted")
	}
	if _, e = parseUnit(strings.ReplaceAll(raw, ".timer", ".service"), "cloud-8021x-renew.service"); e == nil {
		t.Fatal("missing actual service PID properties accepted")
	}
}
