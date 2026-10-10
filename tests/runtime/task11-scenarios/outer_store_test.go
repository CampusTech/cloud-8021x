package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOuterStoreExclusiveProtectedFilesAndDescriptorBindings(t *testing.T) {
	path, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(path, 0700); e != nil {
		t.Fatal(e)
	}
	s, e := openOuterStore(path, os.Getuid())
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	name := "task11-" + strings.Repeat("1", 32) + "-1.json"
	raw := []byte(" {\"schema\":1} ")
	if e = s.create("requests", name, raw); e != nil {
		t.Fatal(e)
	}
	got, e := s.read("requests", name, 65536)
	if e != nil || !bytes.Equal(got, raw) {
		t.Fatal("protected exact bytes missing", e)
	}
	if s.create("requests", name, raw) == nil {
		t.Fatal("irreversible request overwritten")
	}
	for _, dir := range []string{"other", "../requests", "/requests"} {
		if s.create(dir, name, raw) == nil {
			t.Fatal("unknown directory accepted")
		}
	}
	for _, bad := range []string{"../outside", "arbitrary.json", name + "/child"} {
		if s.create("results", bad, raw) == nil {
			t.Fatal("generic pathname accepted")
		}
	}
	file := filepath.Join(path, "requests", name)
	if e = os.Chmod(file, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = s.read("requests", name, 65536); e == nil {
		t.Fatal("public credential/record read")
	}
	_ = os.Chmod(file, 0600)
	if e = os.Link(file, file+".link"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.read("requests", name, 65536); e == nil {
		t.Fatal("shared hardlinked input accepted")
	}
}
func TestOuterStoreRefusesSymlinkOrReplacedPrivateDirectories(t *testing.T) {
	path, _ := filepath.EvalSymlinks(t.TempDir())
	_ = os.Chmod(path, 0700)
	s, e := openOuterStore(path, os.Getuid())
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	name := "task11-" + strings.Repeat("1", 32) + "-1.json"
	if e = s.create("requests", name, []byte("{}")); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(filepath.Join(path, "requests"), filepath.Join(path, "old")); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink("old", filepath.Join(path, "requests")); e != nil {
		t.Fatal(e)
	}
	if _, e = s.read("requests", name, 65536); e == nil {
		t.Fatal("symlink directory accepted")
	}
	if e = os.Chmod(path, 0755); e != nil {
		t.Fatal(e)
	}
	if s.create("results", name, []byte("{}")) == nil {
		t.Fatal("root binding mode changed")
	}
}
