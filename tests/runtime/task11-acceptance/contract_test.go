package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShippingPlanNeverSubstitutesMarkersOrSkipsPeer(t *testing.T) {
	steps, err := stagePlan("cutover")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range steps {
		got = append(got, s.Node+":"+s.Operation)
	}
	want := "blue-primary:capture,blue-primary:transfer,green-primary:prepare,blue-secondary:capture,blue-secondary:transfer,green-secondary:prepare,green-primary:activate,green-secondary:activate,green-primary:activate"
	if strings.Join(got, ",") != want {
		t.Fatalf("unsafe cutover order: %v", got)
	}
	for _, op := range []string{"capture", "source-key", "prepare", "resume-source"} {
		argv, err := shippingCommand(op)
		if err != nil || argv[0] != incoming+"/cloud-8021x" || !strings.Contains(strings.Join(argv, " "), "--incoming") {
			t.Fatalf("not actual staged CLI: %q %v", argv, err)
		}
	}
	for _, op := range []string{"activate", "deactivate", "rollback-proof"} {
		argv, err := shippingCommand(op)
		if err != nil || argv[0] != "/usr/local/bin/cloud-8021x" || strings.Contains(strings.Join(argv, " "), "--incoming") {
			t.Fatalf("not installed CLI: %q %v", argv, err)
		}
	}
	if _, err := stagePlan("all"); err == nil {
		t.Fatal("unreviewed automatic all-stages accepted")
	}
	if _, err := shippingCommand("sh"); err == nil {
		t.Fatal("arbitrary command accepted")
	}
}

func TestPrivateTransferRefusesLinkAndPreservesExistingOnFailure(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "receipt.json")
	payload := []byte("synthetic private envelope")
	if err := atomicPrivate(path, payload, os.Getuid()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private mode: %v %v", info, err)
	}
	b, err := readPrivate(path, 1024, os.Getuid())
	if err != nil || !bytes.Equal(b, payload) {
		t.Fatalf("readback: %v", err)
	}
	if _, err := readPrivate(path, 1, os.Getuid()); err == nil {
		t.Fatal("unbounded read")
	}
	target := filepath.Join(dir, "victim")
	if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := atomicPrivate(path, payload, os.Getuid()); err == nil {
		t.Fatal("followed destination symlink")
	}
	b, err = os.ReadFile(target)
	if err != nil || string(b) != "original" {
		t.Fatal("mutated symlink target")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivate(path, 1024, os.Getuid()); err == nil {
		t.Fatal("read hardlinked private file")
	}
	if err := atomicPrivate(path, payload, os.Getuid()); err == nil {
		t.Fatal("replaced hardlinked private file")
	}
}

func TestTransferSlotsDoNotExposeSigningKeys(t *testing.T) {
	for _, role := range []string{"radius-primary", "radius-secondary"} {
		for _, kind := range []string{"parallel", "rollback"} {
			src, dst, err := receiptPaths(kind, role)
			if err != nil || !strings.HasPrefix(src, "/var/lib/cloud-8021x-bootstrap/") || !strings.HasPrefix(dst, incoming+"/") {
				t.Fatalf("slot %s/%s: %v", kind, role, err)
			}
		}
	}
	for _, pair := range [][2]string{{"parallel-source.key", "radius-primary"}, {"parallel", "../radius-primary"}, {"parallel", "root"}} {
		if _, _, err := receiptPaths(pair[0], pair[1]); err == nil {
			t.Fatal("arbitrary private slot accepted")
		}
	}
}

func TestPrivateTransferRejectsAncestorLinksAndWritableParents(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "safe")
	if err = os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err = atomicPrivate(filepath.Join(target, "receipt"), []byte("private"), os.Getuid()); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked")
	if err = os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err = readPrivate(filepath.Join(link, "receipt"), 1024, os.Getuid()); err == nil {
		t.Fatal("followed ancestor symlink")
	}
	if err = os.Chmod(target, 0777); err != nil {
		t.Fatal(err)
	}
	if err = atomicPrivate(filepath.Join(target, "receipt"), []byte("changed"), os.Getuid()); err == nil {
		t.Fatal("writable parent admitted")
	}
	if err = os.Chmod(target, 0700); err != nil {
		t.Fatal(err)
	}
	b, err := readPrivate(filepath.Join(target, "receipt"), 1024, os.Getuid())
	if err != nil || string(b) != "private" {
		t.Fatal("failed write changed original")
	}
}
