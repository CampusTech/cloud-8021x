package host

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/config"

	"github.com/CampusTech/cloud-8021x/internal/migration"
)

func publicationFixture(phase string) (StatePublication, []byte) {
	digit := map[string]string{"prepared": "1", "archive": "2", "complete": "3"}[phase]
	bundle := migration.Bundle{Version: 1, Node: "radius-primary", Policy: json.RawMessage(`{"version":2,"updated_at":1791453600.123456789,"identities":{},"certificates":{},"hardware_serials":{}}`), ClassKeySHA256: strings.Repeat("a", 64), UsageAbsent: true, SQL: migration.LegacySQL{Status: "absent"}}
	raw, _ := json.Marshal(bundle)
	return StatePublication{Transition: strings.Repeat(digit, 64), Node: bundle.Node, ConfigSHA256: strings.Repeat("b", 64), BundleSHA256: digestBytes(raw), Attempt: 1}, raw
}
func TestInstalledStatePublicationInterruptedOriginalArchive(t *testing.T) {
	if os.Getenv("C8021X_WRITER_FIXTURE") != "task9" {
		t.Skip("owned Linux publication fixture")
	}
	if phase := os.Getenv("C8021X_PUBLICATION_CHILD"); phase != "" {
		p, raw := publicationFixture(phase)
		unlock, e := AcquireWriterOperation()
		if e != nil {
			t.Fatal(e)
		}
		defer unlock()
		if e = PrepareStatePublication(p, raw); e != nil {
			t.Fatal(e)
		}
		if e = ValidateStatePublicationRecovery(p, raw); e == nil {
			t.Fatal("living original helper was accepted")
		}
		dir, _ := publicationDirectory(p)
		if phase == "archive" {
			if e = privateWrite(filepath.Join(dir, "published-bundle.json"), raw, 0600); e != nil {
				t.Fatal(e)
			}
		}
		if phase == "complete" {
			if e = PublishCapturedState(p, raw); e != nil {
				t.Fatal(e)
			}
		}
		return
	}
	if output, e := exec.Command("/usr/sbin/useradd", "--system", "dd-agent").CombinedOutput(); e != nil {
		t.Fatal(e, string(output))
	}
	accounts, e := EnsureAccounts(context.Background())
	if e != nil {
		t.Fatal(e)
	}

	t.Run("capture_read_only", func(t *testing.T) {
		for _, path := range []string{legacyDowngradeGuard, "/var/lib/cloud-8021x/metadata.json", legacyStatePaths["certificates"], "/var/cache/cloud-8021x/runtime/provider.json"} {
			if AllowedFile(path) {
				t.Fatal("read-only state became writable", path)
			}
			if e := Write(File{Path: path, Data: []byte("{}"), UID: 0, GID: 0, Mode: 0600}); e == nil {
				t.Fatal("state mutation accepted", path)
			}
		}
		if fd, e := stateParentDescriptor("/etc/shadow", 0); e == nil {
			_ = fd
			t.Fatal("unapproved root input accepted")
		}
		p, raw := publicationFixture("prepared")
		var b migration.Bundle
		_ = json.Unmarshal(raw, &b)
		for _, path := range []string{legacyStatePaths["policy"], legacyStatePaths["certificates"], "/run/radius-accounting-key"} {
			if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
				t.Fatal(e)
			}
			_ = os.Remove(path)
		}
		class := bytes.Repeat([]byte("k"), 32)
		for path, data := range map[string][]byte{legacyStatePaths["policy"]: b.Policy, legacyStatePaths["certificates"]: []byte(`{"status":"absent"}`), "/run/radius-accounting-key": class} {
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
		if e != nil || captured == nil || !bytes.Equal(captured.Data, b.Policy) {
			t.Fatal("original fixed source capture", e)
		}
		// Installation hands the fixed runtime directory to the isolated Go account after capture.
		if e := os.Chown("/var/lib/cloud-8021x", accounts.RuntimeUID, accounts.RuntimeGID); e != nil {
			t.Fatal(e)
		}
		// Retained current files are read through a distinct fixed read-only path.
		if e := Write(File{Path: daemonPolicySnapshot, Data: b.Policy, UID: accounts.RuntimeUID, GID: accounts.RuntimeGID, Mode: 0644}); e != nil {
			t.Fatal(e)
		}
		for _, directory := range []string{authDirectory, "/var/log/freeradius/radacct"} {
			if e := os.MkdirAll(directory, 0755); e != nil {
				t.Fatal(e)
			}
		}
		cfg := config.Config{InstanceID: p.Node, StateTransition: id}
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
	for _, phase := range []string{"prepared", "archive", "complete"} {
		t.Run(phase, func(t *testing.T) {
			p, raw := publicationFixture(phase)
			dir, _ := publicationDirectory(p)
			if e := protectedDirectory(dir, 0, 0, 0700); e != nil {
				t.Fatal(e)
			}
			var b migration.Bundle
			_ = json.Unmarshal(raw, &b)
			if e := Write(File{Path: daemonPolicySnapshot, Data: b.Policy, Mode: 0644, UID: accounts.RuntimeUID, GID: accounts.RuntimeGID}); e != nil {
				t.Fatal(e)
			}
			child := exec.Command(os.Args[0], "-test.run=^TestInstalledStatePublicationInterruptedOriginalArchive$")
			child.Env = append(os.Environ(), "C8021X_PUBLICATION_CHILD="+phase)
			if output, e := child.CombinedOutput(); e != nil {
				t.Fatal(e, string(output))
			}
			unlock, e := AcquireWriterOperation()
			if e != nil {
				t.Fatal(e)
			}
			defer unlock()
			original, e := readPrivateCache(filepath.Join(dir, "publication-original.json"), 4096)
			if e != nil {
				t.Fatal(e)
			}
			changed := p
			changed.Attempt++
			if e = ValidateStatePublicationRecovery(changed, raw); e == nil {
				t.Fatal("changed attempt accepted")
			}
			if e = ValidateStatePublicationRecovery(p, raw); e != nil {
				t.Fatal(e)
			}
			for range 2 {
				if e = PublishCapturedState(p, raw); e != nil {
					t.Fatal("original exact publication did not resume", e)
				}
			}
			lookup := p
			lookup.Attempt = 0
			completed, ok, err := CompletedStatePublication(lookup, raw)
			if err != nil || !ok || completed.Attempt != p.Attempt {
				t.Fatal("exact completed original unavailable", ok, err)
			}
			changedLookup := lookup
			changedLookup.BundleSHA256 = strings.Repeat("f", 64)
			if _, _, err = CompletedStatePublication(changedLookup, raw); err == nil {
				t.Fatal("changed lookup identity accepted")
			}
			complete, e := readPrivateCache(filepath.Join(dir, "publication-complete.json"), 4096)
			if e != nil || !bytes.Equal(complete, original) {
				t.Fatal("original publication receipt changed", e)
			}
			// Each exact publication artifact independently rejects truncated,
			// substituted, linked or foreign-owned evidence. Restore only fixture bytes.
			for _, name := range []string{"publication-original.json", "publication-complete.json", "published-bundle.json"} {
				path := filepath.Join(dir, name)
				valid, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				for _, mutation := range []string{"short", "owner", "hardlink", "symlink"} {
					t.Run(name+"/"+mutation, func(t *testing.T) {
						other := path + ".fixture"
						switch mutation {
						case "short":
							err = os.WriteFile(path, []byte("{"), 0600)
						case "owner":
							err = os.Chown(path, accounts.RuntimeUID, accounts.RuntimeGID)
						case "hardlink":
							err = os.Link(path, other)
						case "symlink":
							err = os.Rename(path, other)
							if err == nil {
								err = os.Symlink(other, path)
							}
						}
						if err != nil {
							t.Fatal(err)
						}
						if _, _, err = CompletedStatePublication(lookup, raw); err == nil {
							t.Fatal("unsafe completed evidence accepted")
						}
						if err = ValidateStatePublicationRecovery(p, raw); err == nil {
							t.Fatal("unsafe publication evidence accepted")
						}
						if err = PublishCapturedState(p, raw); err == nil {
							t.Fatal("unsafe publication was rewritten")
						}
						if err = os.Remove(path); err != nil {
							t.Fatal(err)
						}
						_ = os.Remove(other)
						if err = os.WriteFile(path, valid, 0600); err != nil {
							t.Fatal(err)
						}
						if err = ValidateStatePublicationRecovery(p, raw); err != nil {
							t.Fatal("fixture restoration failed", err)
						}
					})
				}
			}
			if e = os.WriteFile(filepath.Join(dir, "published-bundle.json"), []byte(`{"foreign":true}`), 0600); e != nil {
				t.Fatal(e)
			}
			if e = ValidateStatePublicationRecovery(p, raw); e == nil {
				t.Fatal("foreign published archive accepted")
			}
		})
	}
}
