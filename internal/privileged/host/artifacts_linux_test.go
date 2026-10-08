package host

import (
	"encoding/json"
	"os"
	"runtime"
	"testing"
)

func TestInstalledArtifactInputs(t *testing.T) {
	if os.Getenv("C8021X_ISOLATION_FIXTURE") != "task8" {
		t.Skip("owned isolated Linux fixture required")
	}
	if e := protectedDirectory(ArtifactDirectory, 0, 0, 0700); e != nil {
		t.Fatal(e)
	}
	binary, configuration := []byte("verified-incoming-executable"), []byte("verified-incoming-config")
	manifest := fixtureManifest()
	manifest.Architecture = runtime.GOARCH
	for i := range manifest.Artifacts {
		manifest.Artifacts[i].Architecture = runtime.GOARCH
	}
	manifest.ApplicationVersion = "fixture-1"
	manifest.ApplicationSHA256 = digestBytes(binary)
	manifest.ConfigSHA256 = digestBytes(configuration)
	data, _ := json.Marshal(manifest)
	for path, value := range map[string][]byte{ArtifactManifest: data, ArtifactDirectory + "/cloud-8021x": binary, ArtifactDirectory + "/config.yaml": configuration} {
		if e := os.WriteFile(path, value, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if files, e := IncomingFiles(); e != nil || len(files) != 2 {
		t.Fatal("valid incoming rejected", e)
	}
	if e := os.WriteFile(ArtifactDirectory+"/cloud-8021x", []byte("changed"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := IncomingFiles(); e == nil {
		t.Fatal("checksum mismatch accepted")
	}
	if e := os.WriteFile(ArtifactDirectory+"/cloud-8021x", binary, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(ArtifactManifest, 0666); e != nil {
		t.Fatal(e)
	}
	if _, e := IncomingFiles(); e == nil {
		t.Fatal("writable manifest accepted")
	}
	if e := os.Chmod(ArtifactManifest, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Link(ArtifactDirectory+"/cloud-8021x", ArtifactDirectory+"/linked"); e != nil {
		t.Fatal(e)
	}
	if _, e := IncomingFiles(); e == nil {
		t.Fatal("multiply-linked incoming accepted")
	}
	if e := os.Remove(ArtifactDirectory + "/linked"); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(ArtifactDirectory+"/cloud-8021x", ArtifactDirectory+"/verified"); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("verified", ArtifactDirectory+"/cloud-8021x"); e != nil {
		t.Fatal(e)
	}
	if _, e := IncomingFiles(); e == nil {
		t.Fatal("symlink incoming accepted")
	}
	if e := os.Remove(ArtifactDirectory + "/cloud-8021x"); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(ArtifactDirectory+"/verified", ArtifactDirectory+"/cloud-8021x"); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(ArtifactDirectory, 0777); e != nil {
		t.Fatal(e)
	}
	if _, e := IncomingFiles(); e == nil {
		t.Fatal("writable incoming directory accepted")
	}
	if e := os.Chmod(ArtifactDirectory, 0700); e != nil {
		t.Fatal(e)
	}
}
