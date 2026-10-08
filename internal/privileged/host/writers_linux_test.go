package host

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestInstalledLegacyWriterFenceRetainsAndRestoresExactFiles(t *testing.T) {
	if os.Getenv("C8021X_WRITER_FIXTURE") != "task9" {
		t.Skip("owned task9 root fixture required")
	}
	for _, path := range append(append([]string{}, legacyWriterCrons...), writerUnitPaths(legacyWriterUnits)...) {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		data := []byte("# old sentinel\n")
		if strings.HasSuffix(path, "radius-usage-collector.service") {
			data = []byte("# Managed radius usage monitor; does not control FreeRADIUS.\n")
		}
		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if output, err := exec.Command("/usr/sbin/useradd", "--system", "--uid", "1001", "freerad").CombinedOutput(); err != nil {
		t.Fatalf("fixture account: %v %s", err, output)
	}
	originalModule := []byte("import sys\ndef cached_name():\n    return 'fixture'\n\nif __name__ == '__main__':\n    sys.exit(main())\n")
	if err := os.MkdirAll(filepath.Dir(legacyVLANModule), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyVLANModule, originalModule, 0644); err != nil {
		t.Fatal(err)
	}
	for _, path := range append(slices.Clone(vlanLineage), legacyVLANModule) {
		if err := os.Chown(path, 1001, 1001); err != nil {
			t.Fatal(err)
		}
	}
	run := func(context.Context, string, ...string) ([]byte, error) {
		return []byte("ActiveState=inactive\nSubState=dead\nMainPID=0\n"), nil
	}
	id, hash := strings.Repeat("a", 64), strings.Repeat("b", 64)
	digest, err := fenceLegacyWriters(context.Background(), id, "radius-primary", hash, run, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range legacyWriterHelpers {
		if output, e := exec.Command(path).CombinedOutput(); e != nil || len(output) != 0 {
			t.Fatalf("queued writer %s: %v %s", path, e, output)
		}
	}
	for _, path := range append(slices.Clone(vlanLineage), legacyVLANModule) {
		command := exec.Command("/bin/sh", "-c", "test -r \"$1\" && ! test -w \"$1\"", "check", path)
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1001, Gid: 1001}}
		if output, e := command.CombinedOutput(); e != nil {
			t.Fatalf("native lineage access %s: %v %s", path, e, output)
		}
	}
	fenced, e := os.ReadFile(legacyVLANModule)
	if e != nil || !bytes.Contains(fenced, []byte("def cached_name():")) || bytes.Contains(fenced, []byte("sys.exit(main())")) {
		t.Fatal("library not preserved", e)
	}
	if len(digest) != 64 {
		t.Fatal("missing durable evidence")
	}
	for _, path := range writerUnitPaths(legacyWriterUnits) {
		target, e := os.Readlink(path)
		if e != nil || target != "/dev/null" {
			t.Fatal("not persistently masked", path, e)
		}
	}
	for _, path := range legacyWriterCrons {
		data, e := os.ReadFile(path)
		if e != nil || !bytes.Contains(data, []byte("fenced")) {
			t.Fatal("cron remained active", e)
		}
	}
	again, err := fenceLegacyWriters(context.Background(), id, "radius-primary", hash, run, func() error { return nil })
	if err != nil || again != digest {
		t.Fatal("same evidence not idempotent", err)
	}
	if _, err = fenceLegacyWriters(context.Background(), id, "radius-primary", strings.Repeat("c", 64), run, func() error { return nil }); err == nil {
		t.Fatal("fence adopted different config")
	}
	lockPath := "/etc/freeradius/3.0/vlan-name-cache.json.lock"
	locked, e := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if e = unix.Flock(int(locked.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		t.Fatal(e)
	}
	if _, e = fenceLegacyWriters(context.Background(), id, "radius-primary", hash, run, func() error { return nil }); e == nil {
		t.Fatal("accepted held lock on completed receipt")
	}
	if e = locked.Close(); e != nil {
		t.Fatal(e)
	}

	// Replace the native tree as a real installation does. Missing Python alone
	// is insufficient; only its completed transaction and exact cache can prove
	// retirement. Preserve the old inode tree for the rollback check below.
	if e = os.Rename(radiusDirectory, radiusParent+"/fixture-prior"); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{radiusDirectory, "/etc/cloud-8021x", "/run/cloud-8021x/credentials", "/run/cloud-8021x-root"} {
		if e = protectedDirectory(p, 0, 0, 0755); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = revalidateLegacyWriterFence(context.Background(), id, "radius-primary", nil, run); e == nil {
		t.Fatal("unproven missing native modules accepted")
	}
	tx, e := BeginTransaction(func(string) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	tree := map[string][]byte{"radiusd.conf": []byte("new-native")}
	files := []File{{Path: "/usr/local/bin/cloud-8021x", Data: []byte("new-binary"), Mode: 0755}, {Path: "/etc/cloud-8021x/config.yaml", Data: []byte("new-config"), Mode: 0600}, {Path: "/run/cloud-8021x/credentials/policy", Data: []byte("pinned"), Mode: 0600}}
	cache, e := tx.CredentialCacheFiles(files, tree)
	if e != nil {
		t.Fatal(e)
	}
	for _, f := range append(append(files, cache...), File{Path: radiusDirectory + "/radiusd.conf", Data: tree["radiusd.conf"], Mode: 0600}) {
		if e = Write(f); e != nil {
			t.Fatal(e)
		}
	}
	tx.receipt.WriterRetirement = &writerRetirement{Transition: id, ReceiptSHA256: digest, Native: map[string]string{"radiusd.conf": digestBytes(tree["radiusd.conf"])}}
	tx.receipt.Phase = "complete"
	if e = tx.CompleteInstalled(); e != nil {
		t.Fatal(e)
	}
	layout := []File{files[2]}
	if _, e = revalidateLegacyWriterFence(context.Background(), id, "radius-primary", layout, run); e != nil {
		t.Fatalf("completed native retirement: %v", e)
	}
	if e = AppendWriterBinding(id, "radius-primary", hash, strings.Repeat("c", 64), digest); e != nil {
		t.Fatal(e)
	}
	original, e := os.ReadFile(filepath.Join(transactionRoot, "writers", id, "receipt.json"))
	if e != nil || digestBytes(original) != digest {
		t.Fatal("upgrade changed original", e)
	}
	if e = os.WriteFile(radiusDirectory+"/foreign.py", []byte("unsafe"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = revalidateLegacyWriterFence(context.Background(), id, "radius-primary", layout, run); e == nil {
		t.Fatal("unbound native tree accepted")
	}
	if e = os.RemoveAll(radiusDirectory); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(radiusParent+"/fixture-prior", radiusDirectory); e != nil {
		t.Fatal(e)
	}
	// A copied rollback changes directory inodes. Only the exact completed
	// transaction and original manifest may add a new protected observation.
	rollback, e := BeginTransaction(func(string) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	if e = rollback.BindWriterRetirement(id, nil); e != nil {
		t.Fatal(e)
	}
	if e = rollback.snapshotRadius(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(radiusDirectory, radiusParent+"/fixture-before-copy"); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(radiusDirectory, 0755); e != nil {
		t.Fatal(e)
	}
	rollback.receipt.TreeSwapped = true
	if e = rollback.restoreRadius(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e = verifyWriterMasks(mustWriterReceipt(t, id)); e == nil {
		t.Fatal("unrecorded copy accepted")
	}
	if e = rollback.recordRollbackLineage(); e != nil {
		t.Fatal(e)
	}
	if e = verifyWriterMasks(mustWriterReceipt(t, id)); e == nil {
		t.Fatal("unfinished rollback accepted")
	}
	if e = rollback.persist("rolled-back"); e != nil {
		t.Fatal(e)
	}
	if e = verifyWriterMasks(mustWriterReceipt(t, id)); e != nil {
		t.Fatal("completed exact copied rollback rejected", e)
	}
	originalDirectoryInfo, e := os.Stat(radiusDirectory)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(radiusDirectory+"/foreign.py", []byte("foreign"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = verifyWriterMasks(mustWriterReceipt(t, id)); e == nil {
		t.Fatal("mutated rollback tree accepted")
	}
	if e = os.Remove(radiusDirectory + "/foreign.py"); e != nil {
		t.Fatal(e)
	}
	if e = os.Chtimes(radiusDirectory, originalDirectoryInfo.ModTime(), originalDirectoryInfo.ModTime()); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(legacyVLANModule, 0600); e != nil {
		t.Fatal(e)
	}
	if e = verifyWriterMasks(mustWriterReceipt(t, id)); e == nil {
		t.Fatal("mutated rollback metadata accepted")
	}
	if e = os.Chmod(legacyVLANModule, 0644); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(radiusDirectory, radiusParent+"/fixture-observed-copy"); e != nil {
		t.Fatal(e)
	}
	if output, e := exec.Command("/usr/bin/cp", "--archive", "--", radiusParent+"/fixture-observed-copy", radiusDirectory).CombinedOutput(); e != nil {
		t.Fatal(e, string(output))
	}
	if e = verifyWriterMasks(mustWriterReceipt(t, id)); e == nil {
		t.Fatal("arbitrary exact-byte copy reused stale tuple observation")
	}
	if e = os.RemoveAll(radiusDirectory); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(radiusParent+"/fixture-observed-copy", radiusDirectory); e != nil {
		t.Fatal(e)
	}
	if err = restoreLegacyWriterFiles(id, run); err != nil {
		t.Fatal(err)
	}
	restored, e := os.ReadFile(legacyVLANModule)
	if e != nil || !bytes.Equal(restored, originalModule) {
		t.Fatal("original library changed", e)
	}
	for _, path := range append(slices.Clone(vlanLineage), legacyVLANModule) {
		var st unix.Stat_t
		if unix.Stat(path, &st) != nil || st.Uid != 1001 {
			t.Fatal("legacy owner not restored", path)
		}
	}
	for _, path := range legacyWriterCrons {
		data, e := os.ReadFile(path)
		if e != nil || string(data) != "# old sentinel\n" {
			t.Fatal("rollback altered old bytes", e)
		}
	}
}

func TestInstalledLegacyWriterRealProcessQuiescence(t *testing.T) {
	if os.Getenv("C8021X_WRITER_FIXTURE") != "task9" {
		t.Skip("owned task9 root fixture required")
	}
	path := "/usr/local/bin/fleet-device-fetch.sh"
	if err := os.WriteFile(path, []byte("#!/bin/sh\nsleep 30 &\nwait\n"), 0755); err != nil {
		t.Fatal(err)
	}
	child := exec.Command("/bin/sh", path)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	var evidence []writerPID
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		processes, e := scanWriterProcesses()
		if e != nil {
			t.Fatal(e)
		}
		evidence = writerProcessEvidence(processes)
		if len(evidence) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(evidence) < 2 {
		t.Fatal("real descendant was not captured", evidence)
	}
	if err := checkObservedWriterProcesses(evidence); err == nil {
		t.Fatal("active writer accepted")
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	if err := checkObservedWriterProcesses(evidence); err == nil {
		t.Fatal("orphaned observed descendant accepted")
	}
	for _, p := range evidence {
		if p.PID != child.Process.Pid {
			_ = unix.Kill(p.PID, unix.SIGKILL)
		}
	}
}

func TestInstalledLegacyWriterRecoveryChild(t *testing.T) {
	if os.Getenv("C8021X_WRITER_RECOVERY_CHILD") != "1" {
		t.Skip("recovery subprocess only")
	}
	unlock, e := AcquireWriterOperation()
	if e != nil {
		t.Fatal(e)
	}
	defer unlock()
	_, e = fenceLegacyWriters(context.Background(), strings.Repeat("d", 64), "radius-primary", strings.Repeat("e", 64), func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("injected interruption after fixed masks")
	}, legacyProcessesQuiescent)
	if e == nil {
		t.Fatal("interruption did not occur")
	}
}
func TestInstalledLegacyWriterInterruptedRecovery(t *testing.T) {
	if os.Getenv("C8021X_WRITER_FIXTURE") != "task9" {
		t.Skip("owned root fixture")
	}
	// Give the subprocess an ordinary original helper rather than the prior test's
	// intentionally running shell. The child acquires the actual operation flock.
	if e := os.WriteFile(legacyWriterHelpers[1], []byte("#!/bin/sh\nexit 0\n"), 0755); e != nil {
		t.Fatal(e)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestInstalledLegacyWriterRecoveryChild$", "-test.v")
	child.Env = append(os.Environ(), "C8021X_WRITER_RECOVERY_CHILD=1")
	if out, e := child.CombinedOutput(); e != nil {
		t.Fatalf("child: %v %s", e, out)
	}
	id, hash := strings.Repeat("d", 64), strings.Repeat("e", 64)
	dir, _ := writerReceiptDirectory(id)
	original, e := os.ReadFile(filepath.Join(dir, "receipt.json"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(dir, "complete")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("interrupted receipt already completed")
	}
	unlock, e := AcquireWriterOperation()
	if e != nil {
		t.Fatal(e)
	}
	defer unlock()
	if other, e := AcquireWriterOperation(); e == nil {
		other()
		t.Fatal("live operation lock ignored")
	}
	run := func(context.Context, string, ...string) ([]byte, error) {
		return []byte("ActiveState=inactive\nSubState=dead\nMainPID=0\n"), nil
	}
	p := legacyWriterHelpers[0]
	if e = os.WriteFile(p, []byte("foreign"), 0755); e != nil {
		t.Fatal(e)
	}
	if _, e = recoverLegacyWriterFence(context.Background(), id, "radius-primary", hash, run); e == nil {
		t.Fatal("unknown interrupted state accepted")
	}
	if _, e = os.Stat(filepath.Join(dir, "complete")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("failed recovery published completion")
	}
	if e = os.WriteFile(p, inertHelper, 0755); e != nil {
		t.Fatal(e)
	}
	before, e := os.Stat(p)
	if e != nil {
		t.Fatal(e)
	}
	lastUnit := writerUnitPaths(legacyWriterUnits)[len(legacyWriterUnits)-1]
	badTemp := filepath.Join(filepath.Dir(lastUnit), ".cloud8021x-mask-"+filepath.Base(lastUnit))
	if e = os.Symlink("/etc/passwd", badTemp); e != nil {
		t.Fatal(e)
	}
	if _, e = recoverLegacyWriterFence(context.Background(), id, "radius-primary", hash, run); e == nil {
		t.Fatal("late foreign temporary accepted")
	}
	afterRejected, e := os.Stat(p)
	if e != nil || !os.SameFile(before, afterRejected) {
		t.Fatal("recovery mutated files before complete temporary validation")
	}
	if e = os.Remove(badTemp); e != nil {
		t.Fatal(e)
	}
	got, e := recoverLegacyWriterFence(context.Background(), id, "radius-primary", hash, run)
	if e != nil || got != digestBytes(original) {
		t.Fatal("exact interrupted recovery", got, e)
	}
	after, e := os.ReadFile(filepath.Join(dir, "receipt.json"))
	if e != nil || !bytes.Equal(after, original) {
		t.Fatal("original recovery evidence altered", e)
	}
}

func TestInstalledLegacyWriterRecoversExactStaleMaskTemporary(t *testing.T) {
	if os.Getenv("C8021X_WRITER_FIXTURE") != "task9" {
		t.Skip("owned fixture")
	}
	path := "/etc/systemd/system/cloud-8021x-sources.service"
	if e := os.WriteFile(path, []byte("[Service]\nExecStart=/usr/local/bin/cloud-8021x sources apply\n"), 0644); e != nil {
		t.Fatal(e)
	}
	temporary := filepath.Join(filepath.Dir(path), ".cloud8021x-mask-"+filepath.Base(path))
	if e := os.Symlink("/dev/null", temporary); e != nil {
		t.Fatal(e)
	}
	if e := maskWriterUnit(path); e != nil {
		t.Fatal("exact interrupted mask could not resume", e)
	}
	if target, e := os.Readlink(path); e != nil || target != "/dev/null" {
		t.Fatal(target, e)
	}
	if e := os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, []byte("original"), 0644); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("/etc/passwd", temporary); e != nil {
		t.Fatal(e)
	}
	if e := maskWriterUnit(path); e == nil {
		t.Fatal("foreign temporary accepted")
	}
}

func mustWriterReceipt(t *testing.T, id string) writerReceipt {
	t.Helper()
	r, _, e := loadWriterReceipt(id)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
