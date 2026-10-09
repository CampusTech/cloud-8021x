package main

import (
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
)

func TestActualAllocationSpecRetainsReservationAcrossFormat(t *testing.T) {
	steps, e := filesystemSteps("green-primary", 768*MiB)
	if e != nil {
		t.Fatal(e)
	}
	if len(steps) != 3 || steps[0].Name != "fallocate" || steps[1].Name != "mkfs" || steps[2].Name != "mount" {
		t.Fatal("reservation must precede formatter and mount")
	}
	if strings.Join(steps[1].Args, " ") != "-t ext4 -E nodiscard -q -m 0 -F "+platformRoot+"/images/green-primary.ext4" {
		t.Fatal("formatter can discard reservation or change filesystem")
	}
	for _, tc := range []struct {
		n string
		b int64
	}{{"green-primary", 512 * MiB}, {"green-primary", GiB}, {"production", 768 * MiB}, {"../escape", 768 * MiB}} {
		if _, e = filesystemSteps(tc.n, tc.b); e == nil {
			t.Fatal("unapproved image admitted")
		}
	}
}
func TestGreenBudgetIncludesActualAppAndFuturePrivateWrites(t *testing.T) {
	if e := validateGreenAvailable(700*MiB, 120*MiB, 80*MiB, 10000); e == nil {
		t.Fatal("512MiB collector plus app and private writes exceed available space")
	}
	if e := validateGreenAvailable(700*MiB, 60*MiB, 64*MiB, 10000); e != nil {
		t.Fatal(e)
	}
	if e := validateGreenAvailable(700*MiB, 60*MiB, 64*MiB, 1); e == nil {
		t.Fatal("inode shortage accepted")
	}
	p := validPlan()
	p.Budget.FreeBytes = 1792*MiB + backingBytes + GiB
	if e := p.Budget.validate(); e != nil {
		t.Fatal("already-present staged inputs were charged twice", e)
	}
	p.Budget.FreeBytes--
	if p.Budget.validate() == nil {
		t.Fatal("outer free reserve was reduced")
	}
}

func TestLowerInstallUsesClosedPublicArchivesAndNoHostNetworkOrPrivateSeed(t *testing.T) {
	in := inputs{Packages: host.Manifest{Artifacts: []host.Artifact{{Name: "datadog-agent", Version: "1:7.84.2-1+campus1", Architecture: "arm64"}}}}
	args := lowerInstallArgs(in)
	joined := strings.Join(args, "\n")
	for _, expected := range []string{"--unit=task11-lower-install", "--property=RootDirectory=" + platformRoot + "/volumes/lower", "--property=PrivateDevices=yes", "--property=MountAPIVFS=yes", "--property=PrivateNetwork=yes", "--property=RuntimeMaxSec=180", "--property=KillMode=control-group", "--property=MemoryMax=512M", "--property=TasksMax=256", "--property=BindReadOnlyPaths=" + publicRoot + "/artifacts:/run/task11-artifacts"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("missing actual lower-install bound %s", expected)
		}
	}
	if args[len(args)-1] != "/run/task11-artifacts/datadog-agent_1:7.84.2-1+campus1_arm64.deb" {
		t.Fatal("literal archive name changed")
	}
	if strings.Contains(joined, originalRoot) || strings.Contains(joined, "/var/cache/cloud-8021x/artifacts") {
		t.Fatal("mixed private incoming directory exposed")
	}
}
