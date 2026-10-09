package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProtectedReadRefusesFilesystemSubstitution(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "value")
	if err := os.WriteFile(path, []byte("preserved"), 0600); err != nil {
		t.Fatal(err)
	}
	want := fileRule{path: path, uid: os.Getuid(), gid: os.Getgid(), mode: 0600, max: 32}
	if _, _, err := readAt(root, want); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readAt(root, want); err == nil {
		t.Fatal("hardlinked credential accepted")
	}
	_ = os.Remove(filepath.Join(root, "alias"))
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readAt(root, want); err == nil {
		t.Fatal("public credential accepted")
	}
	_ = os.Chmod(path, 0600)
	want.max = 2
	if _, _, err := readAt(root, want); err == nil {
		t.Fatal("oversized input accepted")
	}
	want.max = 32
	_ = os.Rename(path, path+"-old")
	if err := os.Symlink(path+"-old", path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readAt(root, want); err == nil {
		t.Fatal("symlink accepted")
	}
	_ = os.Remove(path)
	_ = os.Rename(path+"-old", path)
	d := filepath.Join(root, "writable")
	_ = os.Mkdir(d, 0700)
	_ = os.WriteFile(filepath.Join(d, "value"), []byte("preserved"), 0600)
	_ = os.Chmod(d, 0777)
	want.path = filepath.Join(d, "value")
	if _, _, err := readAt(root, want); err == nil {
		t.Fatal("writable ancestor accepted")
	}
}
