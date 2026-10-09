package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func syntheticHelper(t *testing.T) (string, string) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(dir, "helper")
	b := []byte("#!/bin/sh\nprintf 'checked:%s:%s' \"$1\" \"$HOME\"\n")
	if err = os.WriteFile(name, b, 0700); err != nil {
		t.Fatal(err)
	}
	return name, digest(b)
}
func TestHelperExecutesCheckedFileAfterPathReplacement(t *testing.T) {
	name, pin := syntheticHelper(t)
	cmd, f, err := prepareHelper(context.Background(), name, pin, uint32(os.Geteuid()), "fixed-argument")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err = os.Rename(name, name+".checked"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(name, []byte("#!/bin/sh\nprintf replaced\n"), 0700); err != nil {
		t.Fatal(err)
	}
	// macOS refuses direct exec of /dev/fd scripts. Run the owned script using
	// its interpreter, retaining the exact prepared path/FD and all arguments.
	// Linux exercises direct /proc/self/fd exec without this adaptation.
	if runtime.GOOS == "darwin" {
		cmd.Args = append([]string{"/bin/sh"}, cmd.Args...)
		cmd.Path = "/bin/sh"
	}
	b, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "checked:fixed-argument:/root" {
		t.Fatalf("unchecked replacement executed: %q", b)
	}
}
func TestHelperRejectsUnsafeAncestor(t *testing.T) {
	name, pin := syntheticHelper(t)
	if err := os.Chmod(filepath.Dir(name), 0777); err != nil {
		t.Fatal(err)
	}
	f, err := checkedHelper(name, pin, uint32(os.Geteuid()))
	if f != nil {
		_ = f.Close()
	}
	if err == nil {
		t.Fatal("unsafe writable ancestor accepted")
	}
}

func TestCheckedHelperRejectsUnsafeIdentity(t *testing.T) {
	for _, kind := range []string{"wrong-hash", "symlink", "symlink-ancestor", "hardlink", "writable", "not-executable", "empty", "oversized", "wrong-owner"} {
		t.Run(kind, func(t *testing.T) {
			name, pin := syntheticHelper(t)
			owner := uint32(os.Geteuid())
			switch kind {
			case "wrong-hash":
				pin = digest([]byte("other"))
			case "symlink":
				if err := os.Symlink(name, name+".alias"); err != nil {
					t.Fatal(err)
				}
				name += ".alias"
			case "symlink-ancestor":
				dir := filepath.Dir(name)
				alias := dir + "-alias"
				if err := os.Symlink(dir, alias); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Remove(alias) })
				name = filepath.Join(alias, filepath.Base(name))
			case "hardlink":
				if err := os.Link(name, name+".link"); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := os.Chmod(name, 0777); err != nil {
					t.Fatal(err)
				}
			case "not-executable":
				if err := os.Chmod(name, 0600); err != nil {
					t.Fatal(err)
				}
			case "empty":
				if err := os.Truncate(name, 0); err != nil {
					t.Fatal(err)
				}
				pin = digest(nil)
			case "oversized":
				if err := os.Truncate(name, (32<<20)+1); err != nil {
					t.Fatal(err)
				}
			case "wrong-owner":
				owner++
			}
			f, err := checkedHelper(name, pin, owner)
			if f != nil {
				_ = f.Close()
			}
			if err == nil {
				t.Fatal("unsafe executable accepted")
			}
		})
	}
}
