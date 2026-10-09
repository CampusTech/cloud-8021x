package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestProtectedInputRejectsSymlinkWritableWrongOwnerAndOversize(t *testing.T) {
	dir := t.TempDir()
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	p := filepath.Join(dir, "input")
	if err = os.WriteFile(p, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	read := func(name string, owner uint32, max int64) error { _, e := readAt(fd, name, owner, 0600, max); return e }
	if err = read("input", uint32(os.Geteuid()), 32); err != nil {
		t.Fatal(err)
	}
	if err = read("input", uint32(os.Geteuid()+1), 32); err == nil {
		t.Fatal("wrong owner accepted")
	}
	if err = read("input", uint32(os.Geteuid()), 2); err == nil {
		t.Fatal("oversized secret accepted")
	}
	if err = os.Symlink(p, filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	if read("alias", uint32(os.Geteuid()), 32) == nil {
		t.Fatal("symlink accepted")
	}
	if err = os.Chmod(p, 0660); err != nil {
		t.Fatal(err)
	}
	if read("input", uint32(os.Geteuid()), 32) == nil {
		t.Fatal("writable secret accepted")
	}
}
