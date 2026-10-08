package host

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/templates/systemd"
	"golang.org/x/sys/unix"
)

func TestInstalledProtectedTransactionAndSudo(t *testing.T) {
	if os.Getenv("C8021X_ISOLATION_FIXTURE") != "task8" {
		t.Skip("owned disposable Linux fixture required")
	}
	ctx := context.Background()
	for _, name := range []string{"freerad", "dd-agent"} {
		if out, e := exec.Command("/usr/sbin/useradd", "--system", "--no-create-home", name).CombinedOutput(); e != nil {
			t.Fatalf("fixture account: %v %s", e, out)
		}
	}
	accounts, e := EnsureAccounts(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for _, d := range []string{radiusDirectory + "/mods-enabled", radiusDirectory + "/mods-available"} {
		if e = os.MkdirAll(d, 0755); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.WriteFile(radiusDirectory+"/mods-available/eap", []byte("legacy"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink("../mods-available/eap", radiusDirectory+"/mods-enabled/eap"); e != nil {
		t.Fatal(e)
	}
	units, e := systemd.Render()
	if e != nil {
		t.Fatal(e)
	}
	for path, data := range map[string]string{"/usr/local/bin/cloud-8021x": "actual-prior-binary", "/etc/cloud-8021x/config.yaml": "actual-prior-config"} {
		if e = os.WriteFile(path, []byte(data), 0600); e != nil {
			t.Fatal(e)
		}
	}
	legacyClass := []byte(strings.Repeat("legacy-class-secret", 3))
	if e = os.WriteFile("/run/radius-accounting-key", legacyClass, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Chown("/run/radius-accounting-key", accounts.NativeUID, accounts.NativeGID); e != nil {
		t.Fatal(e)
	}
	if e = CheckLegacyClassKey([]byte(strings.Repeat("different", 8))); e == nil {
		t.Fatal("legacy Class bytes silently rotated")
	}
	if e = CheckLegacyClassKey(legacyClass); e != nil {
		t.Fatal(e)
	}
	legacyClassFile, e := AdoptLegacyClassKey(legacyClass, accounts)
	if e != nil {
		t.Fatal(e)
	}
	files := []File{{Path: "/etc/sudoers.d/cloud-8021x", Data: units["/etc/sudoers.d/cloud-8021x"], Mode: 0440}, {Path: "/run/cloud-8021x/credentials/policy", Data: []byte("synthetic-private"), UID: accounts.RuntimeUID, GID: accounts.RuntimeGID, Mode: 0600}}
	files = append(files, legacyClassFile...)
	legacyDropin := "/etc/systemd/system/freeradius.service.d/accounting-key.conf"
	legacyDependency := []byte("[Unit]\nRequires=radius-accounting-key.service\nAfter=radius-accounting-key.service\n")
	if e = os.WriteFile(legacyDropin, legacyDependency, 0644); e != nil {
		t.Fatal(e)
	}
	files = append(files, File{Path: legacyDropin, Data: units[legacyDropin], Mode: 0644})
	files = append(files, File{Path: "/usr/local/bin/cloud-8021x", Data: []byte("incoming-binary"), Mode: 0755}, File{Path: "/etc/cloud-8021x/config.yaml", Data: []byte("incoming-config"), Mode: 0644})
	if e = PrepareFileDirectories(files); e != nil {
		t.Fatal(e)
	}
	if e = os.Chown(radiusParent, accounts.NativeUID, accounts.NativeGID); e != nil {
		t.Fatal(e)
	}
	recorded := ""
	transaction, e := PrepareTransaction(map[string][]byte{"radiusd.conf": []byte("candidate"), "mods-enabled/eap": []byte("new")}, files, func(id string) error { recorded = id; return nil })
	if e != nil {
		t.Fatal(e)
	}
	if recorded == "" {
		t.Fatal("missing durable receipt reference")
	}
	backend := &activationFixture{active: true, validateError: true}
	if e = transaction.Apply(ctx, backend); e == nil {
		t.Fatal("invalid candidate accepted")
	} else if transaction.receipt.Phase != "rolled-back" {
		t.Fatalf("rollback incomplete: %v", e)
	}
	if link, e := os.Readlink(radiusDirectory + "/mods-enabled/eap"); e != nil || link != "../mods-available/eap" {
		t.Fatal("legacy Debian symlink topology not restored")
	}
	if data, e := os.ReadFile(legacyDropin); e != nil || !bytes.Equal(data, legacyDependency) {
		t.Fatal("legacy key dependency not restored", e)
	}
	var classStat unix.Stat_t
	if unix.Stat("/run/radius-accounting-key", &classStat) != nil || int(classStat.Uid) != accounts.NativeUID {
		t.Fatal("legacy Class owner not restored")
	}
	var parentStat unix.Stat_t
	if unix.Stat(radiusParent, &parentStat) != nil || int(parentStat.Uid) != accounts.NativeUID {
		t.Fatal("legacy parent ownership was not restored")
	}
	for path, want := range map[string]string{"/usr/local/bin/cloud-8021x": "actual-prior-binary", "/etc/cloud-8021x/config.yaml": "actual-prior-config"} {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != want {
			t.Fatal("actual prior release was not restored", path, err)
		}
	}
	for _, event := range backend.events {
		if event == "activate" {
			t.Fatal("invalid candidate restarted service")
		}
	}
	transaction, e = PrepareTransaction(map[string][]byte{"radiusd.conf": []byte("valid"), "mods-enabled/eap": []byte("new")}, files, func(string) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	if e = transaction.Apply(ctx, &activationFixture{active: true}); e != nil {
		t.Fatal(e)
	}
	if e = CheckLegacyClassKey(legacyClass); e != nil {
		t.Fatal("adopted Class unavailable to renewal", e)
	}
	if e = ValidateInstalledUnits(ctx); e != nil {
		t.Fatal(e)
	}
	if data, e := os.ReadFile(filepath.Join(transaction.directory, "receipt.json")); e != nil || !strings.Contains(string(data), `"phase":"complete"`) {
		t.Fatal("completion receipt not durable")
	}
	// Actual UIDs, without membership in freerad, can read only scoped credentials.
	for _, check := range []struct {
		user, path string
		success    bool
	}{
		{"cloud8021x", "/run/cloud-8021x/credentials/policy", true},
		{"freerad", "/run/cloud-8021x/credentials/policy", false},
		{"freerad", legacyClassKey, false},
		{"cloud8021x", legacyClassKey, true},
		{"cloud8021x", credentialCachePath, false},
		{"cloud8021x", "/etc/sudoers.d/cloud-8021x", false},
	} {
		out, e := exec.Command("/usr/sbin/runuser", "--user", check.user, "--", "/usr/bin/cat", check.path).CombinedOutput()
		if (e == nil) != check.success {
			t.Fatalf("user %s access %s unexpected: %v %s", check.user, check.path, e, out)
		}
	}
	// Exercise the installed real root-to-app hook through this exact sudo rule.
	binary, e := os.ReadFile("/fixture/cloud-8021x")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile("/usr/local/bin/cloud-8021x", binary, 0755); e != nil {
		t.Fatal(e)
	}
	configuration, e := os.ReadFile("/fixture/config.yaml")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile("/etc/cloud-8021x/config.yaml", configuration, 0644); e != nil {
		t.Fatal(e)
	}
	leaf := "/run/radius-verified-leaves/fixture.pem"
	if out, e := exec.Command("/usr/bin/openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "/run/fixture-key.pem", "-out", leaf, "-days", "1", "-subj", "/CN=fixture").CombinedOutput(); e != nil {
		t.Fatalf("fixture leaf: %s %v", out, e)
	}
	if e = os.Chown(leaf, accounts.NativeUID, accounts.NativeGID); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(leaf, 0600); e != nil {
		t.Fatal(e)
	}
	command := []string{"--user", "freerad", "--", "/usr/bin/sudo", "-n", "/usr/local/bin/cloud-8021x", "--config", "/etc/cloud-8021x/config.yaml", "radius", "verify-leaf", leaf, strings.Repeat("a", 64)}
	if out, e := exec.Command("/usr/sbin/runuser", command...).CombinedOutput(); e != nil {
		t.Fatalf("installed real sudo leaf hook: %s %v", out, e)
	}
	entries, e := os.ReadDir("/run/radius-certificate-bindings")
	if e != nil || len(entries) != 1 {
		t.Fatalf("root-to-app handoff missing: %v", e)
	}
	if out, e := exec.Command("/usr/sbin/runuser", "--user", "cloud8021x", "--", "/usr/bin/cat", filepath.Join("/run/radius-certificate-bindings", entries[0].Name())).CombinedOutput(); e != nil || len(out) != 64 {
		t.Fatalf("app cannot read real handoff: %s %v", out, e)
	}
	stored, e := os.ReadFile(filepath.Join("/run/radius-certificate-bindings", entries[0].Name()))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = hex.DecodeString(string(stored)); e != nil {
		t.Fatal("handoff is not exact hex fingerprint")
	}
	if out, e := exec.Command("/usr/sbin/runuser", "--user", "freerad", "--", "/usr/bin/cat", filepath.Join("/run/radius-certificate-bindings", entries[0].Name())).CombinedOutput(); e == nil {
		t.Fatalf("freerad could read app-only handoff %s", out)
	}
	command[len(command)-2] = "/run/radius-verified-leaves/../fixture-key.pem"
	if out, e := exec.Command("/usr/sbin/runuser", command...).CombinedOutput(); e == nil {
		t.Fatalf("installed sudo accepted traversal %s", out)
	}
	// sudo must reject every command except the fixed completed-leaf handoff.
	if out, e := exec.Command("/usr/sbin/runuser", "--user", "freerad", "--", "/usr/bin/sudo", "-n", "/usr/bin/id").CombinedOutput(); e == nil {
		t.Fatalf("generic root proxy allowed %s", out)
	}
}
