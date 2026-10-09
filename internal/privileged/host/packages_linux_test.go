package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"

	"github.com/CampusTech/cloud-8021x/internal/adapters/freeradius/native"
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
	incoming := Manifest{Schema: 1, Architecture: runtime.GOARCH, CollectorSHA256: strings.Repeat("c", 64), PostgresCASHA256: strings.Repeat("d", 64)}
	for _, name := range requiredArtifacts {
		if !radiusPackage(name) {
			version := MonitoringVersion
			if name == "step-ca" {
				version = StepCAVersion
			}
			incoming.Artifacts = append(incoming.Artifacts, build(name, version, ArtifactDirectory))
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
	if len(plan.Previous) != 1 || len(plan.Absent) != 3 {
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
	tree := map[string][]byte{}
	if err = filepath.WalkDir(radiusDirectory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(radiusDirectory, path)
		if err != nil {
			return err
		}
		tree[relative] = data
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	masked, companionReady, observedPreparation := false, false, false
	cfg, err := config.Load("/fixture/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Bootstrap.LocalAddress, cfg.Bootstrap.PeerAddress = "10.9.0.1", "10.9.0.2"
	expected, err := native.ExpectedReadiness(cfg, tree["certs/server-cert.pem"])
	if err != nil {
		t.Fatal(err)
	}
	expected.Ready = true
	secret := []byte(strings.Repeat("a", 40))
	listener, err := net.Listen("tcp", "10.9.0.1:18122")
	if err != nil {
		t.Fatal(err)
	}
	policy := &http.Server{Handler: native.ReadinessHandler(secret, []string{"10.9.0.1"}, func(context.Context) (native.Readiness, error) { return expected, nil }), ReadHeaderTimeout: time.Second}
	go func() { _ = policy.Serve(listener) }()
	defer func() { _ = policy.Close() }()
	var process *exec.Cmd
	stop := func() {
		if process != nil {
			_ = process.Process.Kill()
			_ = process.Wait()
			process = nil
		}
	}
	defer stop()
	start := func() error {
		process = exec.Command("/usr/sbin/freeradius", "-d", radiusDirectory, "-f", "-l", "stdout")
		process.Env = native.Environment([]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"})
		if err := process.Start(); err != nil {
			return err
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			probe, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
			err := native.ProbeStatus(probe, "10.9.0.1:18121", secret)
			cancel()
			if err == nil {
				return nil
			}
			time.Sleep(50 * time.Millisecond)
		}
		return errors.New("package fixture native status unavailable")
	}
	backend := &RadiusBackend{Companions: true, Local: "10.9.0.1", Peer: "10.9.0.2", Secret: secret, Expected: expected}
	backend.status = func(context.Context, string, []byte) error { return nil }
	backend.readiness = func(context.Context, string, []byte, native.Readiness) error { return nil }
	backend.caHealth = func(context.Context) error {
		if !masked {
			return errors.New("native mask released before CA readiness")
		}
		return nil
	}
	backend.collectorStart = func(context.Context) error {
		if !masked {
			return errors.New("native mask released before collector readiness")
		}
		companionReady = true
		return nil
	}
	backend.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		action := strings.Join(args, " ")
		if strings.Contains(action, "--property=LoadState") {
			return []byte("loaded\n"), nil
		}
		if strings.HasPrefix(action, "show ") {
			if transaction.receipt.Phase == "prepared" || transaction.receipt.Phase == "applying" {
				observedPreparation = true
				if !masked {
					return nil, errors.New("simulated daemon Wants starts native during candidate preparation/validation")
				}
			}
			if process != nil {
				return []byte("ActiveState=active\nSubState=running\nMainPID=123\n"), nil
			}
			return []byte("ActiveState=inactive\nSubState=dead\nMainPID=0\n"), nil
		}
		switch action {
		case "mask --runtime freeradius.service":
			masked = true
		case "unmask --runtime freeradius.service":
			masked = false
		case "restart cloud-8021x.service":
			if !masked {
				return nil, errors.New("daemon Wants starts unready native")
			}
		case "stop freeradius.service":
			stop()
		case "start freeradius.service":
			if masked || !companionReady {
				return nil, errors.New("native start before companion readiness")
			}
			return nil, start()
		}
		return nil, nil
	}
	if err = transaction.MaskPackages(ctx, backend); err != nil {
		t.Fatal(err)
	}
	if err = transaction.InstallPackages(ctx, plan); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat("/run/task8-maintainer-started"); !os.IsNotExist(err) {
		t.Fatal("maintainer script started a service")
	}
	if !masked {
		t.Fatal("package installation released barrier")
	}
	if err = transaction.Prepare(tree, nil); err != nil {
		t.Fatal(err)
	}
	if err = transaction.Apply(ctx, backend); err != nil {
		t.Fatalf("guarded package-changing Apply: %v", err)
	}
	if !observedPreparation || !companionReady || masked {
		t.Fatal("preparation/readiness release not exercised")
	}
	if err = transaction.Rollback(ctx, backend, false); err != nil {
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

// This fixture runs only inside an owned Debian 13 container, with synthetic
// package payloads. It exercises dpkg removal and a persisted interrupted plan.
func TestIsolatedUtilityRetirementAndInterruptedRollback(t *testing.T) {
	if os.Getenv("C8021X_PACKAGE_FIXTURE") != "task10" {
		t.Skip("owned Debian 13 package fixture required")
	}
	ctx := context.Background()
	if err := os.MkdirAll(rollbackArtifactDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	fixtureDependency := "libpq5 (>= 1.0.0-1)"
	build := func(name, version, base string, utility bool) Artifact {
		t.Helper()
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "DEBIAN"), 0755); err != nil {
			t.Fatal(err)
		}
		control := "Package: " + name + "\nVersion: " + version + "\nArchitecture: " + runtime.GOARCH + "\nMaintainer: Owned Task10 fixture\nDescription: disposable protected package fixture\n"
		if name == "step-ca" && fixtureDependency != "" {
			control += "Depends: " + fixtureDependency + "\n"
		}
		if err := os.WriteFile(filepath.Join(dir, "DEBIAN/control"), []byte(control), 0644); err != nil {
			t.Fatal(err)
		}
		if utility {
			if err := os.MkdirAll(filepath.Join(dir, "usr/bin"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "usr/bin", name), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
				t.Fatal(err)
			}
			if name == "step-cli" {
				for script, body := range map[string]string{"postinst": "update-alternatives --install /usr/bin/step step /usr/bin/step-cli 50", "prerm": "update-alternatives --remove step /usr/bin/step-cli"} {
					if err := os.WriteFile(filepath.Join(dir, "DEBIAN", script), []byte("#!/bin/sh\nset -e\n"+body+"\n"), 0755); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
		a := Artifact{Name: name, Version: version, Architecture: runtime.GOARCH}
		file := filepath.Join(base, a.filename())
		if out, err := exec.Command("/usr/bin/dpkg-deb", "--build", dir, file).CombinedOutput(); err != nil {
			t.Fatalf("build fixture: %s %v", out, err)
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		a.SHA256 = hex.EncodeToString(sum[:])
		return a
	}
	old := Manifest{Schema: 1, Architecture: runtime.GOARCH}
	for _, name := range []string{"step-cli", "step-kms-plugin", "libpq5"} {
		a := build(name, "0.30.2-1", rollbackArtifactDirectory, name != "libpq5")
		old.Artifacts = append(old.Artifacts, a)
		if _, err := execute(ctx, "/usr/bin/dpkg", "--install", filepath.Join(rollbackArtifactDirectory, a.filename())); err != nil {
			t.Fatal(err)
		}
	}
	incoming := Manifest{Schema: 1, Architecture: runtime.GOARCH, CollectorSHA256: strings.Repeat("c", 64), PostgresCASHA256: strings.Repeat("d", 64)}
	for _, name := range requiredArtifacts {
		version := MonitoringVersion
		if name == "step-ca" {
			version = StepCAVersion
		}
		if radiusPackage(name) {
			version = RadiusVersion
		}
		incoming.Artifacts = append(incoming.Artifacts, build(name, version, ArtifactDirectory, false))
	}
	incoming.Artifacts = append(incoming.Artifacts, build("libpq5", "1.0.0-1", ArtifactDirectory, false))
	if _, err := PreparePackages(ctx, incoming); err == nil {
		t.Fatal("retired utilities accepted without archives manifest")
	}
	data, _ := json.Marshal(old)
	if err := os.WriteFile(rollbackArtifactDirectory+"/manifest.json", data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("/usr/local/bin", 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/usr/local/bin/step", []byte("unmanaged"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := PreparePackages(ctx, incoming); err == nil {
		t.Fatal("unmanaged shadow utility accepted")
	}
	if err := os.Remove("/usr/local/bin/step"); err != nil {
		t.Fatal(err)
	}
	for i, a := range incoming.Artifacts {
		if a.Name != "step-ca" {
			continue
		}
		fixtureDependency = "missing-fixture-dependency (>= 1)"
		incoming.Artifacts[i] = build(a.Name, a.Version, ArtifactDirectory, false)
		if _, err := PreparePackages(ctx, incoming); err == nil {
			t.Fatal("incomplete dependency closure accepted before package mutation")
		}
		fixtureDependency = "libpq5 (>= 1.0.0-1)"
		incoming.Artifacts[i] = build(a.Name, a.Version, ArtifactDirectory, false)
	}
	plan, err := PreparePackages(ctx, incoming)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Retired) != 2 || len(plan.Previous) != 3 {
		t.Fatalf("retirement plan: %#v", plan)
	}
	checkpoint, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err = plan.install(ctx); err != nil {
		t.Fatal(err)
	}
	upgraded, err := installedPackages()
	if err != nil || upgraded["libpq5"].Version != "1.0.0-1" {
		t.Fatal("dependency upgrade missing", err)
	}
	for _, path := range []string{"/usr/bin/step", "/usr/bin/step-cli", "/usr/bin/step-kms-plugin"} {
		if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("retired executable remains: %s %v", path, err)
		}
	}
	var recovered PackagePlan
	if err = json.Unmarshal(checkpoint, &recovered); err != nil {
		t.Fatal(err)
	}
	if err = recovered.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	current, err := installedPackages()
	if err != nil {
		t.Fatal(err)
	}
	if len(current) != len(plan.Installed) {
		t.Fatalf("unexpected restored package count: %d", len(current))
	}
	for _, a := range old.Artifacts {
		if !samePackage(a, current[a.Name]) {
			t.Fatal("exact cold utility package not restored")
		}
	}
	if err = verifyRetiredUtilities(ctx, current); err != nil {
		t.Fatal(err)
	}
	if target, err := filepath.EvalSymlinks("/usr/bin/step"); err != nil || target != "/usr/bin/step-cli" {
		t.Fatal("official alternative not restored", err)
	}
	// A compatible newer dependency is retained without any matching old archive;
	// both forward installation and rollback must leave its version untouched.
	newer := build("libpq5", "1.1.0-1", ArtifactDirectory, false)
	if _, err = execute(ctx, "/usr/bin/dpkg", "--install", filepath.Join(ArtifactDirectory, newer.filename())); err != nil {
		t.Fatal(err)
	}
	retained, err := PreparePackages(ctx, incoming)
	if err != nil {
		t.Fatal(err)
	}
	if !samePackage(retained.Retained["libpq5"], newer) || len(retained.Previous) != 2 {
		t.Fatal("newer satisfied dependency not retained")
	}
	if err = retained.install(ctx); err != nil {
		t.Fatal(err)
	}
	if err = retained.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	current, err = installedPackages()
	if err != nil || !samePackage(current["libpq5"], newer) {
		t.Fatal("newer dependency changed during transition", err)
	}
	legacy := PackagePlan{Installed: map[string]Artifact{}}
	for _, name := range retiredArtifacts {
		legacy.Installed[name] = current[name]
	}
	if err = legacy.Rollback(ctx); err != nil {
		t.Fatal("historical product-only journal rejected pre-existing dependency", err)
	}
	legacy.InventoryVersion = 1
	if err = legacy.Rollback(ctx); err == nil {
		t.Fatal("current journal ignored unrecorded dependency")
	}
}
