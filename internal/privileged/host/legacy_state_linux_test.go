package host

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/config"
)

func TestInstalledParallelStateInputsRemainReadOnly(t *testing.T) {
	if os.Getenv("C8021X_WRITER_FIXTURE") != "task9" {
		t.Skip("owned Linux state fixture")
	}
	if output, e := exec.Command("/usr/sbin/useradd", "--system", "dd-agent").CombinedOutput(); e != nil {
		t.Fatal(e, string(output))
	}
	accounts, e := EnsureAccounts(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	t.Run("capture_read_only", func(t *testing.T) {
		for _, path := range []string{"/var/lib/cloud-8021x/metadata.json", legacyStatePaths["certificates"], "/var/cache/cloud-8021x/runtime/provider.json"} {
			if AllowedFile(path) {
				t.Fatal("read-only state became writable", path)
			}
			if e := Write(File{Path: path, Data: []byte("{}"), UID: 0, GID: 0, Mode: 0600}); e == nil {
				t.Fatal("state mutation accepted", path)
			}
		}
		// The current fingerprint downgrade marker is deliberately root-written
		// by PublishParallelAuthorization; it is not an imported cache output.
		if !AllowedFile(legacyDowngradeGuard) {
			t.Fatal("protected adoption cannot preserve the enforcement marker")
		}
		if fd, e := stateParentDescriptor("/etc/shadow", 0); e == nil {
			_ = fd
			t.Fatal("unapproved root input accepted")
		}
		policy := []byte(`{"version":2,"updated_at":1791453600.123456789,"identities":{},"certificates":{},"hardware_serials":{}}`)
		for _, path := range []string{legacyStatePaths["policy"], legacyStatePaths["certificates"], "/run/radius-accounting-key"} {
			if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
				t.Fatal(e)
			}
			_ = os.Remove(path)
		}
		class := bytes.Repeat([]byte("k"), 32)
		for path, data := range map[string][]byte{legacyStatePaths["policy"]: policy, legacyStatePaths["certificates"]: []byte(`{"status":"absent"}`), "/run/radius-accounting-key": class} {
			if e := os.WriteFile(path, data, 0600); e != nil {
				t.Fatal(e)
			}
		}
		_ = os.Remove(legacyDowngradeGuard)
		id := strings.Repeat("9", 64)
		dir, _ := writerReceiptDirectory(id)
		if e := protectedDirectory(dir, 0, 0, 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.Chown("/var/lib/cloud-8021x", 0, 0); e != nil {
			t.Fatal(e)
		}
		captured, e := readLegacyStateComponent("policy", accounts.NativeUID)
		if e != nil || captured == nil || !bytes.Equal(captured.Data, policy) {
			t.Fatal("original fixed source capture", e)
		}
		// Installation hands the fixed runtime directory to the isolated Go account after capture.
		if e := os.Chown("/var/lib/cloud-8021x", accounts.RuntimeUID, accounts.RuntimeGID); e != nil {
			t.Fatal(e)
		}
		// Retained current files are read through a distinct fixed read-only path.
		if e := Write(File{Path: daemonPolicySnapshot, Data: policy, UID: accounts.RuntimeUID, GID: accounts.RuntimeGID, Mode: 0644}); e != nil {
			t.Fatal(e)
		}
		for _, directory := range []string{authDirectory, "/var/log/freeradius/radacct"} {
			if e := os.MkdirAll(directory, 0755); e != nil {
				t.Fatal(e)
			}
		}
		cfg := config.Config{InstanceID: "radius-primary", StateTransition: id}
		cfg.Paths.InventoryFile = daemonPolicySnapshot
		cfg.Paths.MetadataFile = "/var/lib/cloud-8021x/metadata.json"
		cfg.Paths.AuthLogDir = authDirectory
		cfg.Paths.AccountingSpoolDir = "/var/log/freeradius/radacct"
		if _, e := CaptureDaemonState(cfg, accounts, class); e != nil {
			t.Fatal(e)
		}
		_ = os.Remove(legacyStatePaths["certificates"])
		if e := os.Symlink("/etc/passwd", legacyStatePaths["certificates"]); e != nil {
			t.Fatal(e)
		}
		if _, e := readLegacyStateComponent("certificates", 0); e == nil {
			t.Fatal("substituted state link accepted")
		}
		_ = os.Remove(legacyStatePaths["certificates"])
	})
}
