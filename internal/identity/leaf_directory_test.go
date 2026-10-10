package identity

import (
	"bytes"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func leafDirectoryFixture(t *testing.T) string {
	t.Helper()
	var base string
	var err error
	if os.Geteuid() == 0 {
		base, err = os.MkdirTemp("/run", "cloud8021x-leaf-test-")
		if err == nil {
			t.Cleanup(func() { _ = os.RemoveAll(base) })
		}
	} else {
		base, err = filepath.EvalSymlinks(t.TempDir())
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	return base
}
func TestLeafDirectoryRejectsEverySymlinkComponent(t *testing.T) {
	base := leafDirectoryFixture(t)
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	leafFile(t, target, []byte("outside"))
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if dir, err := OpenLeafDirectory(link, os.Geteuid()); err == nil {
		_ = dir.Close()
		t.Fatal("followed final directory link")
	}
	ancestor := filepath.Join(base, "ancestor")
	if err := os.Symlink(base, ancestor); err != nil {
		t.Fatal(err)
	}
	if dir, err := OpenLeafDirectory(filepath.Join(ancestor, "target"), os.Geteuid()); err == nil {
		_ = dir.Close()
		t.Fatal("followed ancestor link")
	}
}
func TestLeafDirectoryDescriptorRemainsPinnedAfterPathReplacement(t *testing.T) {
	base := leafDirectoryFixture(t)
	fixed := filepath.Join(base, "verified-leaves")
	outside := filepath.Join(base, "outside")
	for _, p := range []string{fixed, outside} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	leafFile(t, fixed, []byte("approved original"))
	leafFile(t, outside, []byte("redirected outside"))
	dir, err := OpenLeafDirectory(fixed, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	if err := os.Rename(fixed, filepath.Join(base, "original")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, fixed); err != nil {
		t.Fatal(err)
	}
	data, err := dir.Read("leaf.pem")
	block, _ := pem.Decode(data)
	if err != nil || block == nil || !bytes.Equal(block.Bytes, []byte("approved original")) {
		t.Fatal("relative read reopened replaced directory", err)
	}
}
func TestLeafDirectoryValidatesPrivateOwnershipAndUnwritableAncestry(t *testing.T) {
	base := leafDirectoryFixture(t)
	leafDir := filepath.Join(base, "verified-leaves")
	if err := os.Mkdir(leafDir, 0700); err != nil {
		t.Fatal(err)
	}
	if dir, err := OpenLeafDirectory(leafDir, os.Geteuid()+1); err == nil {
		_ = dir.Close()
		t.Fatal("accepted wrong leaf-directory owner")
	}
	if err := os.Chmod(leafDir, 0755); err != nil {
		t.Fatal(err)
	}
	if dir, err := OpenLeafDirectory(leafDir, os.Geteuid()); err == nil {
		_ = dir.Close()
		t.Fatal("accepted public leaf directory")
	}
	if err := os.Chmod(leafDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0777); err != nil {
		t.Fatal(err)
	}
	if dir, err := OpenLeafDirectory(leafDir, os.Geteuid()); err == nil {
		_ = dir.Close()
		t.Fatal("accepted replaceable writable parent")
	}
}
func TestLeafDirectoryRejectsHardlinkedSymlinkedOrPublicLeavesAndEscapes(t *testing.T) {
	for _, kind := range []string{"hardlink", "symlink", "public", "escape", "absolute"} {
		t.Run(kind, func(t *testing.T) {
			base := leafDirectoryFixture(t)
			dirPath := filepath.Join(base, "verified-leaves")
			if err := os.Mkdir(dirPath, 0700); err != nil {
				t.Fatal(err)
			}
			path := leafFile(t, dirPath, []byte("verified leaf"))
			name := "leaf.pem"
			switch kind {
			case "hardlink":
				if err := os.Link(path, filepath.Join(base, "outside.pem")); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, filepath.Join(base, "outside.pem")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(base, "outside.pem"), path); err != nil {
					t.Fatal(err)
				}
			case "public":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "escape":
				name = "../outside.pem"
			case "absolute":
				name = path
			}
			dir, err := OpenLeafDirectory(dirPath, os.Geteuid())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = dir.Close() }()
			if _, err := dir.Read(name); err == nil {
				t.Fatal("unsafe leaf input accepted", kind)
			}
		})
	}
}

func TestPrivilegedLeafAncestryRequiresRootAndNoWritableParent(t *testing.T) {
	// Overlay filesystems may legitimately report one directory link; only
	// unlinked directories are unavailable. Input files still require one link.
	st := unix.Stat_t{Mode: unix.S_IFDIR | 0755, Uid: 0, Nlink: 1}
	if !safeLeafAncestor(st, 0) {
		t.Fatal("rejected protected root-owned single-link directory")
	}
	st.Uid = 100
	if safeLeafAncestor(st, 0) {
		t.Fatal("root accepted producer-owned ancestor")
	}
	st.Uid = 0
	st.Mode = unix.S_IFDIR | unix.S_ISVTX | 0777
	if safeLeafAncestor(st, 0) {
		t.Fatal("root accepted writable sticky ancestor")
	}
	st.Mode = unix.S_IFDIR | 0755
	st.Nlink = 0
	if safeLeafAncestor(st, 0) {
		t.Fatal("accepted unlinked ancestor")
	}
}
