package main

import (
	"strings"
	"testing"
)

func TestLowerExcludesIdentitySecretsAndInterruptedRuntime(t *testing.T) {
	for _, p := range []string{"/etc/machine-id", "/etc/ssh/ssh_host_ed25519_key", "/etc/cloud8021x-task11-fixture", "/var/lib/cloud8021x-task11/control/original-seed/api/seed.json", "/var/lib/postgresql/17/main/PG_VERSION", "/run/key", "/etc/systemd/system/task11-acceptance.service"} {
		if allowedLower(p) {
			t.Fatalf("private/runtime path admitted: %s", p)
		}
	}
	if !allowedLower("/usr/bin/sudo") || !allowedLower("/var/lib/dpkg/status") {
		t.Fatal("real package base omitted")
	}
	m := lowerManifest{Schema: 1, Entries: []lowerEntry{{Path: "/usr/bin/x", Kind: "file", Mode: 0755, Bytes: 1024, SHA256: strings.Repeat("a", 64)}}}
	if m.validate() != nil {
		t.Fatal("bounded public file refused")
	}
	m.Entries = append(m.Entries, m.Entries[0])
	if m.validate() == nil {
		t.Fatal("duplicated lower entry accepted")
	}
}
