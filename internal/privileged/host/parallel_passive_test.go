package host

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestParallelPassiveConditionsCoverProductionUnits(t *testing.T) {
	files := ParallelPassiveFiles()
	want := []string{"cloud-8021x.service", "freeradius.service", "step-ca.service", "step-ca-rsa.service", "cloud-8021x-renew.service", "cloud-8021x-sources.service", "datadog-agent.service", "datadog-agent-ddot.service"}
	if len(files) != len(want) {
		t.Fatal("incomplete passive barriers")
	}
	for i, unit := range want {
		if files[i].Path != "/etc/systemd/system/"+unit+".d/parallel.conf" || !strings.Contains(string(files[i].Data), "ConditionPathExists=/var/lib/cloud-8021x-bootstrap/parallel-active.json") {
			t.Fatal("production unit lacks persistent activation barrier")
		}
	}
}

func TestParallelPassiveCleanUninstalledUnitIsPositivelyAbsent(t *testing.T) {
	run := func(context.Context, string, ...string) ([]byte, error) {
		return []byte("LoadState=not-found\nActiveState=inactive\nMainPID=0\n"), errors.New("unit not found")
	}
	if err := parallelUnitsStopped(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{"LoadState=not-found\nActiveState=active\nMainPID=0\n", "LoadState=not-found\nActiveState=inactive\nMainPID=12\n", "LoadState=error\nActiveState=inactive\nMainPID=0\n", ""} {
		bad := func(context.Context, string, ...string) ([]byte, error) { return []byte(out), errors.New("unknown") }
		if parallelUnitsStopped(context.Background(), bad) == nil {
			t.Fatal("unknown/live unit accepted")
		}
	}
}
