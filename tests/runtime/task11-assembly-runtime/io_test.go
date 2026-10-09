package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinnedReadRejectsSubstitutedSymlinkAndTrailingPlan(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "input")
	if err := os.WriteFile(p, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPinned(p, strings.Repeat("a", 64), 64); err == nil {
		t.Fatal("changed bytes accepted")
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(p, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := readPinned(alias, digest([]byte("private")), 64); err == nil {
		t.Fatal("symlink accepted")
	}
	if b, err := readPinned(p, digest([]byte("private")), 64); err != nil || string(b) != "private" {
		t.Fatal("exact original rejected")
	}
}
func TestCandidateWriterNeverInstallsAndRefusesReuse(t *testing.T) {
	parent, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(parent, "candidates")
	o := output{Files: map[string]candidate{"blue-primary/etc/test": {Data: []byte("secret"), SHA256: digest([]byte("secret")), Owner: "root", Group: "root", Mode: 0600}}}
	if err := writeCandidates(dir, o); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "files/blue-primary/etc/test"))
	if err != nil || string(b) != "secret" {
		t.Fatal("candidate missing")
	}
	if err = writeCandidates(dir, o); err == nil {
		t.Fatal("candidate overwrite permitted")
	}
	bad := filepath.Join(t.TempDir(), "candidate")
	o.Files = map[string]candidate{"../escape": {Data: []byte("bad")}}
	if err = writeCandidates(bad, o); err == nil {
		t.Fatal("path escape accepted")
	}
}
func TestPrivateSeedInputRejectsPublicMode(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "seed")
	if err = os.WriteFile(p, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = readPrivatePinned(p, digest([]byte("secret")), 64); err == nil {
		t.Fatal("public secret seed accepted")
	}
}
func TestOutputRejectsSymlinkAndAttackerWritableParent(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(parent, "real")
	if err = os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(parent, "alias")
	if err = os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	o := output{Files: map[string]candidate{"blue-primary/etc/test": {Data: []byte("private"), SHA256: digest([]byte("private")), Owner: "root", Group: "root", Mode: 0600}}}
	if err = writeCandidates(filepath.Join(alias, "candidate"), o); err == nil {
		t.Fatal("symlink ancestor accepted for private candidate output")
	}
	if err = os.Chmod(real, 0777); err != nil {
		t.Fatal(err)
	}
	if err = writeCandidates(filepath.Join(real, "candidate"), o); err == nil {
		t.Fatal("attacker-writable output parent accepted")
	}
}
func TestHeldCandidateDirectoryRejectsSubstitutionAndIndexSymlink(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Run("renamed-root", func(t *testing.T) {
		root := filepath.Join(parent, "held")
		w, err := newCandidateWriter(root)
		if err != nil {
			t.Fatal(err)
		}
		defer w.close()
		if err = w.write("files/blue-primary/etc/first", []byte("first-private")); err != nil {
			t.Fatal(err)
		}
		moved := filepath.Join(parent, "moved")
		outside := filepath.Join(parent, "outside")
		if err = os.Mkdir(outside, 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.Rename(root, moved); err != nil {
			t.Fatal(err)
		}
		if err = os.Symlink(outside, root); err != nil {
			t.Fatal(err)
		}
		if err = w.write("files/blue-primary/etc/second", []byte("must-not-escape")); err == nil {
			t.Fatal("replaced retained root accepted")
		}
		entries, err := os.ReadDir(outside)
		if err != nil || len(entries) != 0 {
			t.Fatal("private bytes escaped retained authority")
		}
		if _, err = os.Stat(filepath.Join(moved, "candidate-index.json")); !os.IsNotExist(err) {
			t.Fatal("failed output marked complete")
		}
	})
	t.Run("index-symlink", func(t *testing.T) {
		root := filepath.Join(parent, "index")
		w, err := newCandidateWriter(root)
		if err != nil {
			t.Fatal(err)
		}
		defer w.close()
		victim := filepath.Join(parent, "victim")
		if err = os.WriteFile(victim, []byte("unchanged"), 0600); err != nil {
			t.Fatal(err)
		}
		if err = os.Symlink(victim, filepath.Join(root, "candidate-index.json")); err != nil {
			t.Fatal(err)
		}
		if err = w.write("candidate-index.json", []byte("private index")); err == nil {
			t.Fatal("index symlink followed")
		}
		b, err := os.ReadFile(victim)
		if err != nil || string(b) != "unchanged" {
			t.Fatal("unrelated file truncated")
		}
	})
	t.Run("ancestor-permissions", func(t *testing.T) {
		p := filepath.Join(parent, "mutable")
		if err = os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
		w, err := newCandidateWriter(filepath.Join(p, "root"))
		if err != nil {
			t.Fatal(err)
		}
		defer w.close()
		if err = os.Chmod(p, 0777); err != nil {
			t.Fatal(err)
		}
		if w.write("candidate-index.json", []byte("index")) == nil {
			t.Fatal("newly attacker-writable parent accepted")
		}
	})
}
