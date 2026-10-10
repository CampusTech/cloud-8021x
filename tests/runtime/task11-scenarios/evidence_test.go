package main

import (
	"strings"
	"testing"
)

func TestRebootContinuityRequiresRetiredLeaderAndPreservedCollector(t *testing.T) {
	before := continuity{Machine: "task11-green-primary", MachineID: strings.Repeat("1", 32), Root: "/var/lib/cloud8021x-task11/roots/task11-green-primary", BootID: "11111111-2222-4333-8444-555555555555", Leader: 100, StartTicks: 17, ApplicationSHA256: strings.Repeat("a", 64), ConfigSHA256: strings.Repeat("b", 64), CollectorBacking: "/var/lib/cloud-8021x-bootstrap/collector.ext4", CollectorBytes: 512 << 20, CollectorDevice: 7, CollectorInode: 22, CollectorFilesystem: "ext4", CollectorOptions: "rw,nodev,nosuid,noexec", Epoch: "1800000000", Deployment: "task11-green", WorkersActive: true}
	after := before
	after.BootID = "22222222-3333-4444-8555-666666666666"
	after.Leader = 101
	after.StartTicks = 30
	if err := verifyContinuity(before, after, true); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*continuity){func(v *continuity) { v.BootID = before.BootID }, func(v *continuity) { v.CollectorInode++ }, func(v *continuity) { v.CollectorBytes-- }, func(v *continuity) { v.Epoch = "new-epoch" }, func(v *continuity) { v.ConfigSHA256 = "" }, func(v *continuity) { v.CollectorOptions = "rw,nodev,nosuid" }, func(v *continuity) { v.WorkersActive = false }} {
		bad := after
		mutate(&bad)
		if verifyContinuity(before, bad, true) == nil {
			t.Fatalf("foreign/lost persistent state accepted: %+v", bad)
		}
	}
	if verifyContinuity(before, after, false) == nil {
		t.Fatal("command exit without old leader retirement accepted")
	}
}

func TestAckIsNeverLedgerOrDeliveryProof(t *testing.T) {
	e := accountingEvidence{PacketACKs: 5}
	if verifyAccountingEvidence(e) == nil {
		t.Fatal("ACK-only evidence accepted as delivery")
	}
	e.LedgerVerified = true
	if verifyAccountingEvidence(e) == nil {
		t.Fatal("ledger-only evidence accepted as collector delivery")
	}
	e.ControllerVerifiedCloudSHA256 = strings.Repeat("a", 64)
	if verifyAccountingEvidence(e) == nil {
		t.Fatal("intake proof with no frozen independent event pin accepted")
	}
}
