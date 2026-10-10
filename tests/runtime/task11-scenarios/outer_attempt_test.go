package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOuterAttemptIsExclusiveAndOnlySamePinnedCAPhaseCanReopen(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	_ = os.Chmod(root, 0700)
	s, e := openOuterStore(root, os.Getuid())
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	p := pureNASPlan()
	pin := strings.Repeat("a", 64)
	a, e := bindOuterAttempt(s, p, pin, "", bytes.NewReader(bytes.Repeat([]byte{1}, 16)))
	if e != nil || a.AttemptID != "task11-"+strings.Repeat("01", 16) {
		t.Fatal("exclusive attempt absent", e)
	}
	if _, e = bindOuterAttempt(s, p, pin, "", bytes.NewReader(bytes.Repeat([]byte{2}, 16))); e == nil {
		t.Fatal("accounting automatically rerun")
	}
	p.Scenario.Scenario = "ca-continuity"
	p.Scenario.Case = "ca-ec-continuity"
	a, e = bindOuterAttempt(s, p, pin, "original", bytes.NewReader(bytes.Repeat([]byte{3}, 16)))
	if e != nil {
		t.Fatal(e)
	}
	b, e := bindOuterAttempt(s, p, pin, "adopted", nil)
	if e != nil || a != b {
		t.Fatal("CA immutable attempt changed", e)
	}
	if _, e = bindOuterAttempt(s, p, strings.Repeat("b", 64), "passive", nil); e == nil {
		t.Fatal("changed CA plan accepted")
	}
	if _, e = bindOuterAttempt(s, p, pin, "original", nil); e == nil {
		t.Fatal("original issuance automatically rerun")
	}
	p.Scenario.Case = "ca-rsa-continuity"
	if _, e = bindOuterAttempt(s, p, pin, "adopted", nil); e == nil {
		t.Fatal("adopted phase invented original history")
	}
}
