package host

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstalledFreshInitialOriginalHelper(t *testing.T) {
	if os.Getenv("C8021X_WRITER_FIXTURE") != "task9" {
		t.Skip("owned Linux fixture")
	}
	id, node, hash, bundle := strings.Repeat("9", 64), "radius-primary", strings.Repeat("8", 64), strings.Repeat("7", 64)
	snapshot := []byte(`{"version":2,"updated_at":1791453600,"identities":{"uuid":{"device_id":"fleet:1","groups":[],"enrolled":true}},"certificates":{},"hardware_serials":{}}`)
	if os.Getenv("C8021X_FRESH_INITIAL_CHILD") == "task9" {
		release, e := AcquireWriterOperation()
		if e != nil {
			t.Fatal(e)
		}
		defer release()
		if e = PrepareFreshInventory(id, node, hash, bundle, snapshot, 92); e != nil {
			t.Fatal(e)
		}
		if e = ProveFreshInventoryStopped(id, node, hash, bundle, 92); e == nil {
			t.Fatal("live original accepted")
		}
		return
	}
	child := exec.CommandContext(context.Background(), os.Args[0], "-test.run=^TestInstalledFreshInitialOriginalHelper$")
	child.Env = append(os.Environ(), "C8021X_FRESH_INITIAL_CHILD=task9")
	if out, e := child.CombinedOutput(); e != nil {
		t.Fatal(e, string(out))
	}
	release, e := AcquireWriterOperation()
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	if e = ProveFreshInventoryStopped(id, node, hash, bundle, 92); e != nil {
		t.Fatal(e)
	}
	if e = ProveFreshInventoryStopped(id, node, hash, bundle, 93); e == nil {
		t.Fatal("foreign attempt accepted")
	}
	if _, e = ReadFreshInventory(id, node, hash, strings.Repeat("1", 64)); e == nil {
		t.Fatal("foreign original bundle accepted")
	}
	got, e := ReadFreshInventory(id, node, hash, bundle)
	if e != nil || !bytes.Equal(got, snapshot) {
		t.Fatal("original snapshot changed", e)
	}
	if e = PrepareFreshInventory(id, node, hash, bundle, bytes.ReplaceAll(snapshot, []byte("1791453600"), []byte("1791453700")), 93); e == nil {
		t.Fatal("refetched observation accepted")
	}
	if e = PrepareFreshInventory(id, node, hash, bundle, snapshot, 93); e != nil {
		t.Fatal("exact no-commit continuation", e)
	}
	if e = ProveFreshInventoryStopped(id, node, hash, bundle, 93); e == nil {
		t.Fatal("live continuation accepted")
	}
	dir, _ := writerReceiptDirectory(id)
	path := filepath.Join(dir, "fresh-inventory.json")
	if e = os.Link(path, path+".fixture-link"); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadFreshInventory(id, node, hash, bundle); e == nil {
		t.Fatal("multiply linked original accepted")
	}
	if e = os.Remove(path + ".fixture-link"); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, []byte("{"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadFreshInventory(id, node, hash, bundle); e == nil {
		t.Fatal("short original accepted")
	}

}
