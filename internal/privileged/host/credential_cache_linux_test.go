package host

import (
	"bytes"
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
