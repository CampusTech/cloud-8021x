package host

import (
	"encoding/json"
	"os"
	"runtime"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/config"
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
	ca := []byte("exact-public-postgres-ca")
	manifest.PostgresCASHA256 = digestBytes(ca)
	data, _ := json.Marshal(manifest)
	for path, value := range map[string][]byte{ArtifactManifest: data, ArtifactDirectory + "/cloud-8021x": binary, ArtifactDirectory + "/config.yaml": configuration, IncomingPostgresCAFile: ca} {
		if e := os.WriteFile(path, value, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if files, e := IncomingFiles(); e != nil || len(files) != 3 {
		t.Fatal("valid incoming rejected", e)
	}
	db := config.Defaults().Database
	db.CAFile, db.InstanceCAPEMSHA256 = PostgresCAFile, manifest.PostgresCASHA256
	preflight, gotCA, err := IncomingDatabase(db)
	if err != nil || string(gotCA) != string(ca) || preflight.CAFile != IncomingPostgresCAFile || db.CAFile != PostgresCAFile {
		t.Fatal("fresh prepublication trust unavailable or installed config mutated", err)
	}
	if e := os.WriteFile(IncomingPostgresCAFile, []byte("changed trust"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, _, err := IncomingDatabase(db); err == nil {
		t.Fatal("changed incoming CA accepted")
	}
	if _, err := IncomingFiles(); err == nil {
		t.Fatal("changed CA entered publication transaction")
	}
	if e := os.WriteFile(IncomingPostgresCAFile, ca, 0600); e != nil {
		t.Fatal(e)
	}
	bad := db
	bad.InstanceCAPEMSHA256 = digestBytes([]byte("different-pin"))
	if _, _, err := IncomingDatabase(bad); err == nil {
		t.Fatal("configuration and manifest CA mismatch accepted")
	}
	if e := os.Rename(IncomingPostgresCAFile, ArtifactDirectory+"/trusted-ca"); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("trusted-ca", IncomingPostgresCAFile); e != nil {
		t.Fatal(e)
	}
	if _, _, err := IncomingDatabase(db); err == nil {
		t.Fatal("symlink incoming CA accepted")
	}
	if e := os.Remove(IncomingPostgresCAFile); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(ArtifactDirectory+"/trusted-ca", IncomingPostgresCAFile); e != nil {
		t.Fatal(e)
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
