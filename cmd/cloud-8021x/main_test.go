package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestExecutableNamesUseUnifiedDaemonCommand(t *testing.T) {
	directory := t.TempDir()
	canonical := filepath.Join(directory, "cloud-8021x")
	build := exec.Command("go", "build", "-ldflags=-X main.version=release-fixture", "-o", canonical, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	binary, err := os.ReadFile(canonical)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"acme-authz-webhook", "acme-authz-webhook-linux-amd64", "acme-authz-webhook-linux-arm64"} {
		alias := filepath.Join(directory, name)
		if err := os.WriteFile(alias, binary, 0755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(alias, "version")
		if out, err := cmd.CombinedOutput(); err != nil || string(out) != "release-fixture\n" {
			t.Fatalf("alias version: %s %v", out, err)
		}
		cmd = exec.Command(alias, "--help")
		if out, err := cmd.CombinedOutput(); err != nil || !bytes.Contains(out, []byte("Cloud 802.1X daemon and protected operations")) {
			t.Fatalf("executable name selected a different runtime: %s %v", out, err)
		}
		cmd = exec.Command(alias, "serve", "--config", filepath.Join(directory, "missing.yaml"))
		cmd.Env = []string{"PATH=/usr/bin:/bin"}
		if out, err := cmd.CombinedOutput(); err == nil || !bytes.Contains(out, []byte("missing.yaml")) || bytes.Contains(out, []byte("FLEET_API_TOKEN")) {
			t.Fatalf("serve did not use unified configuration: %s %v", out, err)
		}
	}
	cmd := exec.Command(canonical, "--help")
	if out, err := cmd.CombinedOutput(); err != nil || !bytes.Contains(out, []byte("Cloud 802.1X daemon and protected operations")) {
		t.Fatalf("canonical command changed: %s %v", out, err)
	}
}
