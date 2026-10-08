package host

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/migration"
)

func TestInstalledFreshAbsenceRefusesPartialFootprint(t *testing.T) {
	if os.Getenv("C8021X_FRESH_FIXTURE") != "task9" {
		t.Skip("owned empty Linux fixture")
	}
	if e := os.WriteFile("/etc/machine-id", []byte(strings.Repeat("1", 32)+"\n"), 0444); e != nil {
		t.Fatal(e)
	}
	id, node, hash := strings.Repeat("6", 64), "radius-primary", strings.Repeat("5", 64)
	class := bytes.Repeat([]byte("k"), 32)
	if e := os.MkdirAll("/var/lib/mysql", 0755); e != nil {
		t.Fatal(e)
	}
	if fresh, e := PrepareFreshState(id, node, hash, class); e == nil || fresh {
		t.Fatal("partial SQL footprint accepted", e)
	}
	if e := os.Remove("/var/lib/mysql"); e != nil {
		t.Fatal(e)
	}
	fresh, e := PrepareFreshState(id, node, hash, class)
	if e != nil || !fresh {
		t.Fatal(fresh, e)
	}
	stopped := func(context.Context, string, ...string) ([]byte, error) {
		return []byte("ActiveState=inactive\nSubState=dead\nMainPID=0\n"), nil
	}
	if _, e = fenceLegacyWriters(context.Background(), id, node, hash, stopped, legacyProcessesQuiescent); e != nil {
		t.Fatal(e)
	}
	raw, e := CaptureFreshState(id, node, hash, class)
	if e != nil {
		t.Fatal(e)
	}
	b, e := migration.DecodeBundle(raw)
	if e != nil || b.FreshAbsenceSHA256 == "" || !bytes.Equal(b.Policy, migration.UnavailableInventory()) {
		t.Fatal(e)
	}
	if _, e = CaptureFreshState(id, node, strings.Repeat("7", 64), class); e == nil {
		t.Fatal("changed fresh config accepted")
	}
	if e = os.MkdirAll(filepath.Dir("/var/lib/mysql/ibdata1"), 0755); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile("/var/lib/mysql/ibdata1", []byte("unknown previous deployment"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = CaptureFreshState(id, node, hash, class); e == nil {
		t.Fatal("new prior-data footprint ignored")
	}
}
