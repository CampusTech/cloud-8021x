package main

import (
	"encoding/json"
	"strings"
	"testing"

	audit "github.com/CampusTech/cloud-8021x/tests/runtime/task11-passive-audit/contract"
)

func TestPassiveWindowBindsActualBaselineAndAllowsZeroReads(t *testing.T) {
	pin := strings.Repeat("a", 64)
	b := passiveWindow{Schema: 1, Kind: "passive-peer-audit", Mode: "baseline", SeedSHA256: pin, Peer: "10.203.11.21", Role: "green-primary", Policy: "passive", FromSequence: 7, ToSequence: 7, BaselineSHA256: pin, EvidenceSHA256: pin}
	raw, _ := json.Marshal(b)
	baseline, err := validatePassiveWindow(raw, pin, "green-primary", nil)
	if err != nil {
		t.Fatal(err)
	}
	f := b
	f.Mode = "final"
	f.ToSequence = 9
	f.OtherPeerEvents = 2
	raw, _ = json.Marshal(f)
	if _, err = validatePassiveWindow(raw, pin, "green-primary", &baseline); err != nil {
		t.Fatal("zero selected reads are valid", err)
	}
	for _, change := range []func(*passiveWindow){func(v *passiveWindow) { v.FromSequence++ }, func(v *passiveWindow) { v.Peer = "10.203.11.22" }, func(v *passiveWindow) { v.BaselineSHA256 = strings.Repeat("b", 64) }, func(v *passiveWindow) { v.MutationAttempts = 1 }, func(v *passiveWindow) { v.Policy = "active" }, func(v *passiveWindow) { v.Events = 1 }} {
		bad := f
		change(&bad)
		raw, _ = json.Marshal(bad)
		if _, err = validatePassiveWindow(raw, pin, "green-primary", &baseline); err == nil {
			t.Fatal("mismatched window accepted")
		}
	}
	var missing map[string]any
	raw, _ = json.Marshal(f)
	_ = json.Unmarshal(raw, &missing)
	delete(missing, "mutation_attempts")
	raw, _ = json.Marshal(missing)
	if _, err = validatePassiveWindow(raw, pin, "green-primary", &baseline); err == nil {
		t.Fatal("omitted mutation observation accepted")
	}
}
func TestPassiveRebootComparisonPreservesContentNotVolatileInodes(t *testing.T) {
	pin := strings.Repeat("a", 64)
	b := audit.Result{Node: "green-primary", Phase: "prepared", Pin: pin, Identity: audit.Identity{MachineID: "stable", Hostname: "task11-green-primary", BootID: "before", PID1: "systemd", PID1Start: "1"}, Preserved: map[string]audit.File{"class-key": {SHA256: pin, Mode: 0600, Bytes: 64, Inode: 1}}, State: map[string]audit.File{"credential-marker": {SHA256: pin, Mode: 0600, Bytes: 64, Inode: 2}}, Collector: audit.Mount{UUID: "filesystem", BackingFile: "fixed-image", Bytes: 512 << 20, Image: audit.File{Bytes: 512 << 20, Inode: 5}}}
	raw, _ := json.Marshal(b)
	var after audit.Result
	_ = json.Unmarshal(raw, &after)
	after.Identity.BootID = "after"
	after.Identity.PID1Start = "2"
	after.Identity.Namespaces = map[string]string{"pid": "new"}
	v := after.State["credential-marker"]
	v.Inode = 9
	after.State["credential-marker"] = v
	after.Collector.Device = "changed-device"
	if err := comparePassiveBoot(b, after); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*audit.Result){func(v *audit.Result) { v.Identity.BootID = b.Identity.BootID }, func(v *audit.Result) { v.Pin = "changed" }, func(v *audit.Result) { v.SQL.WorkSHA256 = "changed" }, func(v *audit.Result) { v.Collector.UUID = "new-filesystem" }, func(v *audit.Result) { v.Collector.Image.Inode++ }, func(v *audit.Result) { v.State = map[string]audit.File{} }} {
		bad := after
		change(&bad)
		if err := comparePassiveBoot(b, bad); err == nil {
			t.Fatal("unpreserved state accepted as reboot proof")
		}
	}
}
