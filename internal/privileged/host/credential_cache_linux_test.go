package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestInstalledCredentialRebootConsistency(t *testing.T) {
	if os.Getenv("C8021X_ISOLATION_FIXTURE") != "task8" {
		t.Skip("owned isolated Linux fixture required")
	}
	for _, path := range []string{"/run/cloud-8021x/credentials", "/run/cloud-8021x-root", radiusDirectory, "/etc/cloud-8021x", "/usr/local/bin"} {
		if e := protectedDirectory(path, 0, 0, 0755); e != nil {
			t.Fatal(e)
		}
	}
	files := []File{{Path: "/usr/local/bin/cloud-8021x", Data: []byte("fixture-binary"), Mode: 0755}, {Path: "/etc/cloud-8021x/config.yaml", Data: []byte("fixture-config"), Mode: 0600}, {Path: "/run/cloud-8021x/credentials/policy", Data: []byte("pinned-policy-secret"), Mode: 0600}}
	tree := map[string][]byte{"radiusd.conf": []byte("pinned-native-secret")}
	transaction, e := BeginTransaction(func(string) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	cache, e := transaction.CredentialCacheFiles(files, tree)
	if e != nil {
		t.Fatal(e)
	}
	for _, f := range append(files, cache...) {
		if e := Write(f); e != nil {
			t.Fatal(e)
		}
	}
	if e := Write(File{Path: radiusDirectory + "/radiusd.conf", Data: tree["radiusd.conf"], Mode: 0600}); e != nil {
		t.Fatal(e)
	}
	layout := []File{files[2]}
	if e := RestoreBootCredentials(layout); e != nil {
		t.Fatalf("staged activation: %v", e)
	}
	if e := os.Remove(credentialMarkerPath); e != nil {
		t.Fatal(e)
	}
	if e := RestoreBootCredentials(layout); e == nil {
		t.Fatal("interrupted candidate restored after reboot")
	}
	transaction.receipt.Phase = "complete"
	if e := transaction.CompleteInstalled(); e != nil {
		t.Fatal(e)
	}
	if e := os.Remove(files[2].Path); e != nil {
		t.Fatal(e)
	}
	if e := RestoreBootCredentials(layout); e != nil {
		t.Fatalf("committed reboot: %v", e)
	}
	got, e := os.ReadFile(files[2].Path)
	if e != nil || !bytes.Equal(got, files[2].Data) {
		t.Fatal("reboot changed credential bytes")
	}
	if e := os.WriteFile(files[2].Path, []byte("out-of-band-rotation"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := RestoreBootCredentials(layout); e == nil {
		t.Fatal("live mismatched credential set silently refreshed")
	}
	values, e := CommittedCredentials(layout)
	if e != nil || !bytes.Equal(values[files[2].Path], files[2].Data) {
		t.Fatal("renewal did not pin committed bytes")
	}
	if e := os.Remove(credentialMarkerPath); e != nil {
		t.Fatal(e)
	}
	if e := Write(File{Path: radiusDirectory + "/radiusd.conf", Data: []byte("different-native-secret"), Mode: 0600}); e != nil {
		t.Fatal(e)
	}
	if e := RestoreBootCredentials(layout); e == nil {
		t.Fatal("credentials restored against different native generation")
	}
}

func TestInstalledBootstrapDiscoveryFiles(t *testing.T) {
	if os.Getenv("C8021X_ISOLATION_FIXTURE") != "task8" {
		t.Skip("owned isolated Linux fixture required")
	}
	path := "/etc/cloud-8021x/sources/clients.conf"
	if e := os.RemoveAll("/etc/cloud-8021x/sources"); e != nil {
		t.Fatal(e)
	}
	files, e := BootstrapDiscoveryFiles(true)
	if e != nil || len(files) != 1 {
		t.Fatalf("missing discovery include preparation: files=%d error=%v", len(files), e)
	}
	if e = PrepareFileDirectories(files); e != nil {
		t.Fatal(e)
	}
	if e = Write(files[0]); e != nil {
		t.Fatal(e)
	}
	old := []byte("# exact existing discovery candidate\nclient preserved { ipaddr = 10.1.2.3 }\n")
	if e = os.WriteFile(path, old, 0640); e != nil {
		t.Fatal(e)
	}
	for _, operation := range []string{"bootstrap", "renew"} {
		files, e = BootstrapDiscoveryFiles(true)
		if e != nil || len(files) != 0 {
			t.Fatalf("%s replaced existing include: %v %v", operation, files, e)
		}
		got, e := os.ReadFile(path)
		if e != nil || !bytes.Equal(got, old) {
			t.Fatal("existing include changed", e)
		}
	}
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink("/etc/passwd", path); e != nil {
		t.Fatal(e)
	}
	if _, e = BootstrapDiscoveryFiles(true); e == nil {
		t.Fatal("unsafe existing include treated as missing")
	}
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
}

func TestInstalledCompletionPublicationRollback(t *testing.T) {
	if os.Getenv("C8021X_ISOLATION_FIXTURE") != "task8" {
		t.Skip("owned isolated Linux fixture required")
	}
	for _, path := range []string{"/run/cloud-8021x/credentials", "/run/cloud-8021x-root", radiusDirectory, "/etc/cloud-8021x", "/usr/local/bin"} {
		if e := protectedDirectory(path, 0, 0, 0755); e != nil {
			t.Fatal(e)
		}
	}
	for _, failure := range []string{"rename", "directory-sync", "committed"} {
		t.Run(failure, func(t *testing.T) {
			files := []File{{Path: "/usr/local/bin/cloud-8021x", Data: []byte("old-binary"), Mode: 0755}, {Path: "/etc/cloud-8021x/config.yaml", Data: []byte("old-config"), Mode: 0600}, {Path: "/run/cloud-8021x/credentials/policy", Data: []byte("old-pinned-policy"), Mode: 0600}}
			tree := map[string][]byte{"radiusd.conf": []byte("old-native")}
			old, e := BeginTransaction(func(string) error { return nil })
			if e != nil {
				t.Fatal(e)
			}
			cache, e := old.CredentialCacheFiles(files, tree)
			if e != nil {
				t.Fatal(e)
			}
			for _, f := range append(append(files, cache...), File{Path: radiusDirectory + "/radiusd.conf", Data: tree["radiusd.conf"], Mode: 0600}) {
				if e = Write(f); e != nil {
					t.Fatal(e)
				}
			}
			old.receipt.Phase = "complete"
			if e = old.CompleteInstalled(); e != nil {
				t.Fatal(e)
			}
			prior, e := os.ReadFile(transactionRoot + "/current.json")
			if e != nil {
				t.Fatal(e)
			}
			next, e := BeginTransaction(func(string) error { return nil })
			if e != nil {
				t.Fatal(e)
			}
			for i := range files {
				files[i].Data = append([]byte("new-"), files[i].Data...)
			}
			cache, e = next.CredentialCacheFiles(files, tree)
			if e != nil {
				t.Fatal(e)
			}
			for _, f := range append(files, cache...) {
				saved, e := Snapshot(f)
				if e != nil {
					t.Fatal(e)
				}
				next.receipt.Files = append(next.receipt.Files, saved)
				if e = Write(f); e != nil {
					t.Fatal(e)
				}
			}
			next.receipt.Phase = "complete"
			e = next.completeInstalled(func(temporary string) error {
				// The prior binding must already be durable before the first
				// publication I/O, not merely available in memory for rollback.
				receiptBytes, err := os.ReadFile(next.directory + "/receipt.json")
				if err != nil {
					t.Fatal(err)
				}
				var receipt Receipt
				if err = json.Unmarshal(receiptBytes, &receipt); err != nil {
					t.Fatal(err)
				}
				saved := receipt.Files[len(receipt.Files)-1]
				if saved.Path != transactionRoot+"/current.json" || !saved.Exists || saved.UID != 0 || saved.GID != 0 || saved.Mode != 0600 || !bytes.Equal(saved.Data, prior) {
					t.Fatal("exact prior completion record not durable before publication")
				}
				if failure == "committed" {
					return publishGeneration(temporary)
				}
				if failure == "directory-sync" {
					if e := os.Rename(temporary, transactionRoot+"/current.json"); e != nil {
						t.Fatal(e)
					}
				}
				return errors.New("injected completion publication " + failure)
			})
			want := "old-pinned-policy"
			if failure == "committed" {
				if e != nil {
					t.Fatal(e)
				}
				// No later reporting error may restore a prior generation.
				if e = next.Rollback(context.Background(), &activationFixture{}, false); e == nil {
					t.Fatal("committed installation rolled back")
				}
				want = "new-old-pinned-policy"
			} else {
				if e == nil {
					t.Fatal("completion failure ignored")
				}
				if e = next.Rollback(context.Background(), &activationFixture{}, false); e != nil {
					t.Fatal(e)
				}
				got, e := os.ReadFile(transactionRoot + "/current.json")
				if e != nil || !bytes.Equal(prior, got) {
					t.Fatalf("prior completion bytes not restored: %v", e)
				}
			}
			layout := []File{files[2]}
			values, e := CommittedCredentials(layout)
			if e != nil || string(values[files[2].Path]) != want {
				t.Fatalf("renewal after rollback: %v", e)
			}
			if e = os.Remove(credentialMarkerPath); e != nil {
				t.Fatal(e)
			}
			if e = os.Remove(files[2].Path); e != nil {
				t.Fatal(e)
			}
			if e = RestoreBootCredentials(layout); e != nil {
				t.Fatalf("offline reboot after rollback: %v", e)
			}
		})
	}
}
