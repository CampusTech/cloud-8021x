package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestProducerPrivateReadsRefuseSubstitutions(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if os.Chmod(root, 0700) != nil {
		t.Fatal("setup")
	}
	path := filepath.Join(root, "input")
	original := []byte(" \n{\"schema\":1}\n ")
	if os.WriteFile(path, original, 0600) != nil {
		t.Fatal("setup")
	}
	raw, e := producerRead(path, os.Getuid(), 64<<10, 0600)
	if e != nil || !bytes.Equal(raw, original) {
		t.Fatalf("opaque bytes changed: %v", e)
	}
	if os.Chmod(path, 0644) != nil {
		t.Fatal("setup")
	}
	if _, e = producerRead(path, os.Getuid(), 64<<10, 0600); e == nil {
		t.Fatal("public private input accepted")
	}
	if os.Chmod(path, 0600) != nil || os.Link(path, filepath.Join(root, "alias")) != nil {
		t.Fatal("setup")
	}
	if _, e = producerRead(path, os.Getuid(), 64<<10, 0600); e == nil {
		t.Fatal("hard-linked private input accepted")
	}
	if os.Remove(filepath.Join(root, "alias")) != nil || os.Symlink(path, filepath.Join(root, "symlink")) != nil {
		t.Fatal("setup")
	}
	if _, e = producerRead(filepath.Join(root, "symlink"), os.Getuid(), 64<<10, 0600); e == nil {
		t.Fatal("symlink input accepted")
	}
	if _, e = producerRead(path, os.Getuid(), 1, 0600); e == nil {
		t.Fatal("oversize input accepted")
	}
}
func TestProducerActualExclusivePublicationRefusesRetryAndPartialState(t *testing.T) {
	in := producerFixture(t)
	bundle, e := prepareNASBundle(in)
	if e != nil {
		t.Fatal(e)
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if os.Chmod(root, 0700) != nil {
		t.Fatal("setup")
	}
	control := filepath.Join(root, "control")
	parent := filepath.Join(root, "nas")
	if os.Mkdir(control, 0700) != nil || os.Mkdir(parent, 0700) != nil {
		t.Fatal("setup")
	}
	dest := filepath.Join(parent, "cloud8021x-task11-nas")
	identity := []byte("{\"schema\":1,\"input_identity\":\"synthetic\"}")
	if e = publishNASDirectories(control, dest, os.Getuid(), bundle, identity); e != nil {
		t.Fatal(e)
	}
	for name, want := range bundle.Materials {
		got, e := producerRead(filepath.Join(dest, name), os.Getuid(), 64<<10, 0600)
		if e != nil || !bytes.Equal(got, want) {
			t.Fatal("actual private material differs")
		}
	}
	for name, want := range bundle.Plans {
		got, e := producerRead(filepath.Join(control, "scenarios", "plans", name), os.Getuid(), 64<<10, 0600)
		if e != nil || !bytes.Equal(got, want) {
			t.Fatal("actual plan differs")
		}
	}
	if publishNASDirectories(control, dest, os.Getuid(), bundle, identity) == nil {
		t.Fatal("completed publication repeated")
	}
	// A foreign/preexisting destination is never repaired; the exclusive claim
	// remains, and a later corrected destination still cannot retry uncertainty.
	control2 := filepath.Join(root, "control2")
	parent2 := filepath.Join(root, "nas2")
	if os.Mkdir(control2, 0700) != nil || os.Mkdir(parent2, 0700) != nil {
		t.Fatal("setup")
	}
	dest2 := filepath.Join(parent2, "cloud8021x-task11-nas")
	if os.Mkdir(dest2, 0700) != nil {
		t.Fatal("setup")
	}
	sentinel := filepath.Join(dest2, "foreign")
	if os.WriteFile(sentinel, []byte("untouched"), 0600) != nil {
		t.Fatal("setup")
	}
	if publishNASDirectories(control2, dest2, os.Getuid(), bundle, identity) == nil {
		t.Fatal("preexisting destination repaired")
	}
	if got, _ := os.ReadFile(sentinel); string(got) != "untouched" {
		t.Fatal("foreign state changed")
	}
	if _, e = os.Stat(filepath.Join(control2, "scenario-preparation.json")); e != nil {
		t.Fatal("uncertain claim erased")
	}
	if os.Remove(sentinel) != nil || os.Remove(dest2) != nil {
		t.Fatal("setup")
	}
	if publishNASDirectories(control2, dest2, os.Getuid(), bundle, identity) == nil {
		t.Fatal("uncertain publication retried")
	}
}

func TestProducerInvalidBundleRefusesBeforeAnyPublication(t *testing.T) {
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if os.Chmod(root, 0700) != nil {
		t.Fatal("setup")
	}
	control := filepath.Join(root, "control")
	parent := filepath.Join(root, "nas")
	if os.Mkdir(control, 0700) != nil || os.Mkdir(parent, 0700) != nil {
		t.Fatal("setup")
	}
	if publishNASDirectories(control, filepath.Join(parent, "cloud8021x-task11-nas"), os.Getuid(), preparedNAS{}, []byte("identity")) == nil {
		t.Fatal("empty bundle accepted")
	}
	entries, e := os.ReadDir(control)
	if e != nil || len(entries) != 0 {
		t.Fatal("invalid bundle had irreversible effects")
	}
	entries, e = os.ReadDir(parent)
	if e != nil || len(entries) != 0 {
		t.Fatal("invalid bundle published private directory")
	}
}
