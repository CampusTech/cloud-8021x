package host

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

func TestInstalledPersistentCollectorQuota(t *testing.T) {
	if os.Getenv("C8021X_STORAGE_FIXTURE") != "task8" {
		t.Skip("owned isolated mount fixture required")
	}
	ctx := context.Background()
	if err := PrepareCollectorStorage(ctx); err != nil {
		t.Fatal(err)
	}
	image, err := os.Stat(collectorImage)
	if err != nil || image.Size() != collectorBytes {
		t.Fatal("queue image size differs", err)
	}
	if err = PrepareCollectorStorage(ctx); err != nil {
		t.Fatal("existing filesystem not adopted", err)
	}
	mount := func() {
		t.Helper()
		if out, err := exec.Command("/usr/bin/mount", "-o", "loop,nodev,nosuid,noexec", collectorImage, "/var/lib/cloud8021x/collector").CombinedOutput(); err != nil {
			t.Fatalf("owned fixture mount: %s %v", out, err)
		}
	}
	unmount := func() {
		t.Helper()
		if out, err := exec.Command("/usr/bin/umount", "/var/lib/cloud8021x/collector").CombinedOutput(); err != nil {
			t.Fatalf("owned fixture unmount: %s %v", out, err)
		}
	}
	mount()
	mounted := true
	defer func() {
		if mounted {
			_ = exec.Command("/usr/bin/umount", "/var/lib/cloud8021x/collector").Run()
		}
	}()
	marker := "/var/lib/cloud8021x/collector/retained-record"
	if err = os.WriteFile(marker, []byte("original-pending-business-record"), 0600); err != nil {
		t.Fatal(err)
	}
	unmount()
	mounted = false
	mount()
	mounted = true
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "original-pending-business-record" {
		t.Fatal("persistent queue lost across remount", err)
	}
	var status unix.Statfs_t
	if err = unix.Statfs("/var/lib/cloud8021x/collector", &status); err != nil {
		t.Fatal(err)
	}
	if uint64(status.Blocks)*uint64(status.Bsize) > collectorBytes {
		t.Fatal("filesystem quota exceeds fixed bound")
	}
	fill, err := os.OpenFile("/var/lib/cloud8021x/collector/fixture-fill", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	block := make([]byte, 1<<20)
	full := false
	for i := 0; i < 520; i++ {
		if _, err = fill.Write(block); err != nil {
			full = errors.Is(err, unix.ENOSPC)
			break
		}
	}
	_ = fill.Close()
	if !full {
		t.Fatal("fixed queue filesystem did not enforce ENOSPC at capacity", err)
	}
	unmount()
	mounted = false
	if err = PrepareCollectorStorage(ctx); err != nil {
		t.Fatal("full existing queue was reformatted or rejected", err)
	}
	mount()
	mounted = true
	data, err = os.ReadFile(marker)
	if err != nil || string(data) != "original-pending-business-record" {
		t.Fatal("full queue original record lost", err)
	}
}
