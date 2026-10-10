package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pureMaterialDirectory(t *testing.T) (string, []byte) {
	t.Helper()
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	raw := []byte("task11-private-material-only")
	if e := os.WriteFile(filepath.Join(root, "radius-secret"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	return root, raw
}
func TestNASMaterialRequiresProtectedExactSingleLinkDescriptor(t *testing.T) {
	root, raw := pureMaterialDirectory(t)
	actual, e := readProtectedNASMaterial(root, "radius-secret", digestBytes(raw), os.Getuid())
	if e != nil || !bytes.Equal(actual, raw) {
		t.Fatalf("protected exact material missing: %v", e)
	}
	for _, name := range []string{"../radius-secret", "/radius-secret", "authority-private.key", "radius-secret/child"} {
		if _, e := readProtectedNASMaterial(root, name, digestBytes(raw), os.Getuid()); e == nil {
			t.Fatal("unknown/path material override accepted")
		}
	}
	if _, e := readProtectedNASMaterial(root, "radius-secret", strings.Repeat("a", 64), os.Getuid()); e == nil {
		t.Fatal("changed material byte identity accepted")
	}
}
func TestNASMaterialRefusesSymlinkHardlinkAndUnsafeModes(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "file-mode", "directory-mode", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			root, raw := pureMaterialDirectory(t)
			file := filepath.Join(root, "radius-secret")
			switch kind {
			case "symlink":
				target := filepath.Join(root, "target")
				if e := os.Rename(file, target); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(target, file); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.Link(file, filepath.Join(root, "alias")); e != nil {
					t.Fatal(e)
				}
			case "file-mode":
				if e := os.Chmod(file, 0640); e != nil {
					t.Fatal(e)
				}
			case "directory-mode":
				if e := os.Chmod(root, 0750); e != nil {
					t.Fatal(e)
				}
			case "oversized":
				raw = bytes.Repeat([]byte("x"), (64<<10)+1)
				if e := os.WriteFile(file, raw, 0600); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := readProtectedNASMaterial(root, "radius-secret", digestBytes(raw), os.Getuid()); e == nil {
				t.Fatal("unsafe material descriptor accepted")
			}
		})
	}
	root, raw := pureMaterialDirectory(t)
	alias := filepath.Join(t.TempDir(), "linked-root")
	if e := os.Symlink(root, alias); e != nil {
		t.Fatal(e)
	}
	if _, e := readProtectedNASMaterial(alias, "radius-secret", digestBytes(raw), os.Getuid()); e == nil {
		t.Fatal("symlink NAS directory accepted")
	}
}
