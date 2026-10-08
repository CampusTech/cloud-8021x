package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInstalledPackageRollbackAndMaintainerSuppression(t *testing.T) {
	if os.Getenv("C8021X_NATIVE_FIXTURE") != "task8" {
		t.Skip("owned package fixture required")
	}
	ctx := context.Background()
	run := func(path string, args ...string) {
		t.Helper()
		if out, err := exec.Command(path, args...).CombinedOutput(); err != nil {
			t.Fatalf("fixture command: %s %v", out, err)
		}
	}
	if err := os.MkdirAll(rollbackArtifactDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/etc/init.d/task8-fixture", []byte("#!/bin/sh\ntouch /run/task8-maintainer-started\n"), 0755); err != nil {
		t.Fatal(err)
	}
	build := func(name, version, base string) Artifact {
		t.Helper()
		directory := t.TempDir()
		if err := os.Mkdir(filepath.Join(directory, "DEBIAN"), 0755); err != nil {
			t.Fatal(err)
		}
		control := "Package: " + name + "\nVersion: " + version + "\nArchitecture: " + runtime.GOARCH + "\nMaintainer: Task8 disposable fixture\nDescription: synthetic package rollback proof\n"
		if err := os.WriteFile(filepath.Join(directory, "DEBIAN/control"), []byte(control), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "DEBIAN/postinst"), []byte("#!/bin/sh\nset -e\n/usr/sbin/invoke-rc.d task8-fixture start\n"), 0755); err != nil {
			t.Fatal(err)
		}
		artifact := Artifact{Name: name, Version: version, Architecture: runtime.GOARCH}
		path := filepath.Join(base, artifact.filename())
		run("/usr/bin/dpkg-deb", "--build", directory, path)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(data)
		artifact.SHA256 = hex.EncodeToString(hash[:])
		return artifact
	}
	old := build("step-cli", "0.9.0-1", rollbackArtifactDirectory)
	if err := withPackagePolicy(ctx, func() error {
		_, err := execute(ctx, "/usr/bin/dpkg", "--install", filepath.Join(rollbackArtifactDirectory, old.filename()))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	prior := Manifest{Schema: 1, Architecture: runtime.GOARCH, Artifacts: []Artifact{old}}
	encoded, _ := json.Marshal(prior)
	if err := os.WriteFile(rollbackArtifactDirectory+"/manifest.json", encoded, 0600); err != nil {
		t.Fatal(err)
	}
	incoming := Manifest{Schema: 1, Architecture: runtime.GOARCH, CollectorSHA256: strings.Repeat("c", 64)}
	for _, name := range requiredArtifacts {
		if !radiusPackage(name) {
			incoming.Artifacts = append(incoming.Artifacts, build(name, "1.0.0-1", ArtifactDirectory))
			continue
		}
		arch := runtime.GOARCH
		if name == "freeradius-common" {
			arch = "all"
		}
		artifact := Artifact{Name: name, Version: RadiusVersion, Architecture: arch}
		data, err := os.ReadFile(filepath.Join("/fixture/artifacts", artifact.filename()))
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(data)
		artifact.SHA256 = hex.EncodeToString(hash[:])
		if err = os.WriteFile(filepath.Join(ArtifactDirectory, artifact.filename()), data, 0600); err != nil {
			t.Fatal(err)
		}
		incoming.Artifacts = append(incoming.Artifacts, artifact)
	}
	plan, err := PreparePackages(ctx, incoming)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Previous) != 1 || len(plan.Absent) != 4 {
		t.Fatalf("incorrect package history: %#v", plan)
	}
	before, err := os.ReadFile(radiusDirectory + "/radiusd.conf")
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := BeginTransaction(func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err = transaction.InstallPackages(ctx, plan); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat("/run/task8-maintainer-started"); !os.IsNotExist(err) {
		t.Fatal("maintainer script started a service")
	}
	if err = os.WriteFile(radiusDirectory+"/radiusd.conf", []byte("package-replaced-config"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = transaction.Rollback(ctx, &activationFixture{}, false); err != nil {
		t.Fatal(err)
	}
	actual, err := installedPackages()
	if err != nil {
		t.Fatal(err)
	}
	if !samePackage(actual["step-cli"], old) {
		t.Fatal("prior exact package not restored")
	}
	for _, name := range plan.Absent {
		if _, ok := actual[name]; ok {
			t.Fatal("new package remained after rollback", name)
		}
	}
	after, err := os.ReadFile(radiusDirectory + "/radiusd.conf")
	if err != nil || string(before) != string(after) {
		t.Fatal("pre-package native config not restored", err)
	}
}
