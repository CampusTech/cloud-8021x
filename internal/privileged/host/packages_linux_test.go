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
