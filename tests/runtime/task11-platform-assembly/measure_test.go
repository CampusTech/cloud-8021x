package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func baseQueryFixture() []byte {
	var b strings.Builder
	for i := 0; i < 347; i++ {
		fmt.Fprintf(&b, "pkg%03d\t1.2:3~test-1\tarm64\tii \n", i)
	}
	return []byte(b.String())
}

func TestMeasureBaseQueryRequiresActualCompleteInventoryAndEmptyAudit(t *testing.T) {
	good := baseQueryFixture()
	if err := validateBaseQuery(good, nil); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{
		"missing-row":     bytes.Join(bytes.Split(good, []byte("\n"))[1:], []byte("\n")),
		"missing-newline": bytes.TrimSuffix(good, []byte("\n")),
		"pending-state":   bytes.Replace(good, []byte("\tii \n"), []byte("\tit \n"), 1),
		"duplicate":       bytes.Replace(good, []byte("pkg001"), []byte("pkg000"), 1),
		"extra-field":     bytes.Replace(good, []byte("pkg000\t"), []byte("pkg000\textra\t"), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if validateBaseQuery(b, nil) == nil {
				t.Fatal("invalid actual query accepted")
			}
		})
	}
	if validateBaseQuery(good, []byte("pending package\n")) == nil {
		t.Fatal("nonempty audit accepted")
	}
}

func openBaseFixture(t *testing.T) (string, int) {
	t.Helper()
	root := protectedPlatformFixture(t)
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return root, fd
}

func baseFixtureFile(t *testing.T, root, logical string, b []byte, mode uint32) {
	t.Helper()
	p := root + logical
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func TestMeasureBaseLowerPreservesUnixModesWithoutPrivateOrLinkTraversal(t *testing.T) {
	root, fd := openBaseFixture(t)
	data := []byte("public executable bytes")
	baseFixtureFile(t, root, "/usr/bin/owned", data, 04755)
	if err := os.Link(root+"/usr/bin/owned", root+"/usr/bin/alias"); err != nil {
		t.Fatal(err)
	}
	baseFixtureFile(t, root, "/etc/passwd", []byte("root:x:0:0::/root:/bin/sh\n"), 0644)
	baseFixtureFile(t, root, "/etc/postgresql-common/user_clusters", []byte("public package helper configuration"), 0644)
	baseFixtureFile(t, root, "/etc/shadow", []byte("must never read"), 0000)
	baseFixtureFile(t, root, "/etc/shadow-", []byte("private backup credential bytes"), 0600)
	baseFixtureFile(t, root, "/etc/gshadow-", []byte("private group backup credential bytes"), 0640)
	baseFixtureFile(t, root, "/etc/shadow.bak", []byte("private alternate backup credential bytes"), 0600)
	baseFixtureFile(t, root, "/etc/ssl/private/key", []byte("must never read"), 0000)
	baseFixtureFile(t, root, "/var/lib/dpkg/status", []byte("public database"), 0644)
	if err := os.Symlink("usr/bin", root+"/bin"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/proc/self/mounts", root+"/etc/mtab"); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(root+"/usr/bin/not-a-file", 0600); err != nil {
		t.Fatal(err)
	}
	m, err := measureLowerAt(context.Background(), fd, 200000, 1664*MiB)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.validate(); err != nil {
		t.Fatal(err)
	}
	entries := map[string]lowerEntry{}
	for _, e := range m.Entries {
		entries[e.Path] = e
	}
	for _, p := range []string{"/usr/bin/owned", "/usr/bin/alias"} {
		if e := entries[p]; e.Kind != "file" || e.Mode != 04755 || e.Bytes != int64(len(data)) || e.SHA256 != digest(data) {
			t.Fatalf("actual Unix mode/hash lost: %+v", e)
		}
	}
	if e := entries["/bin"]; e.Kind != "symlink" || e.Target != "usr/bin" {
		t.Fatalf("usrmerge link lost: %+v", e)
	}
	if e := entries["/etc/postgresql-common/user_clusters"]; e.Kind != "file" {
		t.Fatal("public postgresql-common helper configuration omitted")
	}
	for _, p := range []string{"/etc/shadow", "/etc/shadow-", "/etc/gshadow-", "/etc/shadow.bak", "/etc/ssl/private", "/etc/ssl/private/key", "/etc/mtab", "/usr/bin/not-a-file", "/bin/owned"} {
		if _, ok := entries[p]; ok {
			t.Fatalf("private, special, or traversed path included: %s", p)
		}
	}
}

func TestMeasureBaseLowerBoundsCancellationAndUnsafeModes(t *testing.T) {
	for _, name := range []string{"entry-bound", "byte-bound", "cancelled", "writable"} {
		t.Run(name, func(t *testing.T) {
			root, fd := openBaseFixture(t)
			baseFixtureFile(t, root, "/usr/bin/value", []byte("bounded"), 0644)
			ctx := context.Background()
			entries := 200000
			limit := 1664 * MiB
			switch name {
			case "entry-bound":
				entries = 1
			case "byte-bound":
				limit = 2
			case "cancelled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			case "writable":
				if err := os.Chmod(root+"/usr/bin/value", 0666); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := measureLowerAt(ctx, fd, entries, limit); err == nil {
				t.Fatal("unsafe/unbounded source accepted")
			}
		})
	}
}

func TestMeasureBaseToolIsRetainedRegularSingleLinkAndActuallyHashed(t *testing.T) {
	root := protectedPlatformFixture(t)
	p := root + "/tool"
	data := []byte("fixed executable bytes")
	if err := os.WriteFile(p, data, 0755); err != nil {
		t.Fatal(err)
	}
	if h, err := measureBaseTool(context.Background(), p); err != nil || h != digest(data) {
		t.Fatal("actual tool hash differs", h, err)
	}
	if err := os.Symlink(p, root+"/symlink"); err != nil {
		t.Fatal(err)
	}
	if _, err := measureBaseTool(context.Background(), root+"/symlink"); err == nil {
		t.Fatal("tool symlink followed")
	}
	if err := os.Link(p, root+"/alias"); err != nil {
		t.Fatal(err)
	}
	if _, err := measureBaseTool(context.Background(), p); err == nil {
		t.Fatal("multiply linked tool accepted")
	}
}

func TestMeasureBaseFileChangeAndDirectorySwapRefuse(t *testing.T) {
	root, rootFD := openBaseFixture(t)
	baseFixtureFile(t, root, "/usr/bin/value", []byte("before"), 0644)
	p := root + "/usr/bin/value"
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	var old unix.Stat_t
	if err = unix.Fstat(fd, &old); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	if err = os.WriteFile(p, []byte("changed"), 0644); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	if _, err = hashBaseFile(context.Background(), fd, old, 64); err == nil {
		t.Fatal("file changed after stat accepted")
	}
	dir, err := openBaseDirectory(rootFD, "/usr/bin")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(dir) }()
	if err = os.Rename(root+"/usr/bin", root+"/usr/retained"); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(root+"/usr/bin", 0755); err != nil {
		t.Fatal(err)
	}
	if recheckBaseDirectory(rootFD, dir, "/usr/bin") == nil {
		t.Fatal("swapped source directory accepted")
	}
}

func TestMeasureBaseLoopPairRequiresActualMajorMinorAndNumericalFreeOrder(t *testing.T) {
	facts := []baseLoopFact{{Path: "/dev/loop10", Major: 7, Minor: 10}, {Path: "/dev/loop2", Major: 7, Minor: 2}, {Path: "/dev/loop0", Major: 7, Minor: 0, Occupied: true}}
	pair, err := measuredLoopPair(facts)
	if err != nil || !reflect.DeepEqual(pair, []string{"/dev/loop2", "/dev/loop10"}) {
		t.Fatalf("free observation differs: %v %v", pair, err)
	}
	for name, changed := range map[string][]baseLoopFact{"wrong-minor": {{Path: "/dev/loop2", Major: 7, Minor: 3}, {Path: "/dev/loop10", Major: 7, Minor: 10}}, "wrong-major": {{Path: "/dev/loop2", Major: 8, Minor: 2}, {Path: "/dev/loop10", Major: 7, Minor: 10}}, "duplicate": {facts[0], facts[0]}, "one-free": {facts[0]}} {
		t.Run(name, func(t *testing.T) {
			if _, err := measuredLoopPair(changed); err == nil {
				t.Fatal("unmeasured or ambiguous loop pair accepted")
			}
		})
	}
}

func TestMeasureBaseDryRunHasNoCollectorAndNoOverride(t *testing.T) {
	called := false
	cmd := measureCommandWith(func(context.Context) error { called = true; return nil })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--dry-run"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if called || !strings.Contains(out.String(), "base-observations.json") {
		t.Fatalf("dry-run invoked collector or omitted closed plan: %v %s", called, out.String())
	}
	for _, args := range [][]string{{"--root", "/tmp"}, {"--out", "/tmp"}, {"unexpected"}} {
		c := measureCommandWith(func(context.Context) error { t.Fatal("invalid CLI invoked collector"); return nil })
		c.SetArgs(args)
		c.SetErr(&bytes.Buffer{})
		c.SilenceUsage = true
		c.SilenceErrors = true
		if c.Execute() == nil {
			t.Fatal("arbitrary measurement override accepted")
		}
	}
	actual := command()
	actual.SetOut(&out)
	actual.SetArgs([]string{"measure-base", "--dry-run"})
	if err := actual.Execute(); err != nil {
		t.Fatal("actual Cobra registration refused pure dry-run", err)
	}
}

func TestMeasureBasePublicationIsExactPrivateExclusiveAndBoundToRetainedParent(t *testing.T) {
	root := protectedPlatformFixture(t)
	p := root + "/control/value"
	fd, err := parent(p, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err = publishBaseAt(fd, p, []byte("observed")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(p)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("measurement mode differs", err)
	}
	if publishBaseAt(fd, p, []byte("replacement")) == nil {
		t.Fatal("prior observation overwritten")
	}
	if err = os.Rename(root+"/control", root+"/retained"); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(root+"/control", 0700); err != nil {
		t.Fatal(err)
	}
	if publishBaseAt(fd, root+"/control/new", []byte("observed")) == nil {
		t.Fatal("substituted output directory accepted")
	}
	for _, dir := range []string{"control", "retained"} {
		if _, err = os.Lstat(root + "/" + dir + "/new"); !os.IsNotExist(err) {
			t.Fatal("measurement written after parent substitution")
		}
	}
}
