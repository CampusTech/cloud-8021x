package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestProtectedInputAndExclusiveOutput(t *testing.T) {
	d := protectedPlatformFixture(t)
	var e error
	p := filepath.Join(d, "private")
	if e = os.WriteFile(p, []byte("secret"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = readPinned(p, digest([]byte("changed")), 64, true); e == nil {
		t.Fatal("substituted bytes accepted")
	}
	alias := filepath.Join(d, "alias")
	if e = os.Symlink(p, alias); e != nil {
		t.Fatal(e)
	}
	if _, e = readPinned(alias, digest([]byte("secret")), 64, true); e == nil {
		t.Fatal("symlink accepted")
	}
	if e = publish(p, []byte("replacement"), 0600); e == nil {
		t.Fatal("private output overwritten")
	}
	if b, e := os.ReadFile(p); e != nil || string(b) != "secret" {
		t.Fatal("private input changed")
	}
}

func TestRetainedParentSubstitutionRefusesBeforeCandidateWrite(t *testing.T) {
	d := protectedPlatformFixture(t)
	var e error
	p := d + "/parent/value"
	fd, e := parent(p, true)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = unix.Close(fd) }()
	if e = os.Rename(d+"/parent", d+"/original"); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(d+"/parent", 0700); e != nil {
		t.Fatal(e)
	}
	if e = replaceAt(fd, p, []byte("private"), 0600, os.Geteuid(), os.Getegid()); e == nil {
		t.Fatal("substituted directory accepted")
	}
	for _, base := range []string{"parent", "original"} {
		if _, e = os.Lstat(d + "/" + base + "/value"); !os.IsNotExist(e) {
			t.Fatal("private bytes published after substitution")
		}
	}
}

func TestUnsafeAncestorAndOutputSymlinkAreNotFollowed(t *testing.T) {
	d := protectedPlatformFixture(t)
	var e error
	unsafe := d + "/unsafe"
	if e = os.Mkdir(unsafe, 0777); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(unsafe, 0777); e != nil {
		t.Fatal(e)
	}
	if e = publish(unsafe+"/key", []byte("private"), 0600); e == nil {
		t.Fatal("unsafe ancestor accepted")
	}
	target := d + "/external"
	if e = os.WriteFile(target, []byte("unchanged"), 0600); e != nil {
		t.Fatal(e)
	}
	alias := d + "/alias"
	if e = os.Symlink(target, alias); e != nil {
		t.Fatal(e)
	}
	if e = replaceFile(alias, []byte("candidate"), 0600, os.Geteuid(), os.Getegid()); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(target)
	if e != nil || string(b) != "unchanged" {
		t.Fatal("existing package leaf symlink followed")
	}
	st, e := os.Lstat(alias)
	if e != nil || !st.Mode().IsRegular() {
		t.Fatal("candidate did not replace only the exact leaf")
	}
}

func TestPublicLowerHardlinksBecomeIndependentAndPrivateLinksStillRefuse(t *testing.T) {
	d := protectedPlatformFixture(t)
	var e error
	data := []byte("public package bytes")
	source := d + "/source"
	if e = os.WriteFile(source, data, 0644); e != nil {
		t.Fatal(e)
	}
	if e = os.Link(source, d+"/package-alias"); e != nil {
		t.Fatal(e)
	}
	if f, e := openPinned(source, digest(data), 128, false); e == nil {
		_ = f.Close()
		t.Fatal("helper/private input hardlink accepted")
	}
	target := d + "/copy"
	if e = copyPinnedFile(source, target, digest(data), int64(len(data)), 0644); e != nil {
		t.Fatal(e)
	}
	var st unix.Stat_t
	if unix.Lstat(target, &st) != nil || st.Nlink != 1 {
		t.Fatal("copied lower retained shared inode")
	}
	b, e := os.ReadFile(target)
	if e != nil || string(b) != string(data) {
		t.Fatal("pinned lower bytes changed")
	}
}

// Protected outputs require safe ancestry even when the system temporary root is writable.
func protectedPlatformFixture(t *testing.T) string {
	t.Helper()
	p, err := os.MkdirTemp(".", ".task11-platform-test-")
	if err != nil {
		t.Fatal(err)
	}
	absolute, err := filepath.Abs(p)
	if err != nil {
		_ = os.RemoveAll(p)
		t.Fatal(err)
	}
	p, err = filepath.EvalSymlinks(absolute)
	if err != nil {
		_ = os.RemoveAll(absolute)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(p); err != nil {
			t.Errorf("remove owned private fixture: %v", err)
		}
	})
	return p
}

func TestProtectedPlatformFixtureDoesNotTrustSystemTemp(t *testing.T) {
	unsafe, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(unsafe, 0777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", unsafe)
	refused := filepath.Join(unsafe, "must-refuse")
	if err = publish(refused, []byte("private"), 0600); err == nil {
		t.Fatal("world-writable system temporary root became trusted")
	}
	if _, err = os.Lstat(refused); !os.IsNotExist(err) {
		t.Fatal("private output published beneath unsafe system temp ancestry")
	}
	t.Run("fresh-fixture", func(t *testing.T) {
		p := filepath.Join(protectedPlatformFixture(t), "private")
		if err := publish(p, []byte("private"), 0600); err != nil {
			t.Fatalf("private output fixture inherited unsafe system temp ancestry: %v", err)
		}
		if b, err := readPinned(p, digest([]byte("private")), 64, true); err != nil || string(b) != "private" {
			t.Fatal("protected fixture did not preserve pinned private output", err)
		}
	})
}
