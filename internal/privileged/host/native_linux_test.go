package host

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/freeradius/native"
	"github.com/CampusTech/cloud-8021x/internal/adapters/stepca"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/templates/systemd"
)

func TestInstalledNativeStatusAndPolicyActivation(t *testing.T) {
	if os.Getenv("C8021X_NATIVE_FIXTURE") != "task8" {
		t.Skip("owned campus3 native fixture required")
	}
	ctx := context.Background()
	run := func(path string, args ...string) {
		t.Helper()
		if out, e := exec.Command(path, args...).CombinedOutput(); e != nil {
			t.Fatalf("fixture %s: %s %v", path, out, e)
		}
	}
	run("/usr/sbin/useradd", "--system", "--no-create-home", "dd-agent")
	for _, ip := range []string{"10.9.0.1/32", "10.9.0.2/32"} {
		run("/usr/sbin/ip", "addr", "add", ip, "dev", "lo")
	}
	accounts, e := EnsureAccounts(ctx)
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := config.Load("/fixture/config.yaml")
	if e != nil {
		t.Fatal(e)
	}
	cfg.Bootstrap.LocalAddress = "10.9.0.1"
	cfg.Bootstrap.PeerAddress = "10.9.0.2"
	certificate, e := stepca.LoopbackTLS(stepca.ServerCertificate{}, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{cfg.Database.CAFile, cfg.CA.RootFiles[0]} {
		if e = os.WriteFile(path, certificate.Certificate, 0644); e != nil {
			t.Fatal(e)
		}
	}
	secrets := map[string][]byte{}
	for _, ref := range cfg.Bootstrap.Secrets {
		secrets[ref.File] = []byte(strings.Repeat("a", 40))
	}
	secrets[cfg.Database.NativeWriterDSN.File] = []byte("postgresql://cloud8021x_native:fixture@localhost:5432/cloud8021x?sslmode=verify-full")
	tree, e := native.RenderWithSecrets(cfg, strings.Repeat("a", 32), secrets)
	if e != nil {
		t.Fatal(e)
	}
	tree["certs/server-cert.pem"] = certificate.Certificate
	tree["certs/server-key.pem"] = certificate.Key
	transaction, e := PrepareTransaction(tree, nil, func(string) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	if e = transaction.Apply(ctx, &activationFixture{}); e != nil {
		t.Fatal(e)
	}
	run("/usr/sbin/freeradius", "-d", radiusDirectory, "-XC")
	log, e := os.Create("/run/task8-native.log")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = log.Close() }()
	var process *exec.Cmd
	start := func() {
		t.Helper()
		process = exec.Command("/usr/sbin/freeradius", "-d", radiusDirectory, "-f", "-l", "stdout")
		process.Stdout = log
		process.Stderr = log
		process.Env = native.Environment([]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"})
		if e = process.Start(); e != nil {
			t.Fatal(e)
		}
	}
	stop := func() {
		if process != nil {
			_ = process.Process.Kill()
			_ = process.Wait()
			process = nil
		}
	}
	defer stop()
	start()
	secret := secrets[cfg.Bootstrap.HealthSecret.File]
	waitStatus := func() {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			probe, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
			err := native.ProbeStatus(probe, "10.9.0.1:18121", secret)
			cancel()
			if err == nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		data, _ := os.ReadFile("/run/task8-native.log")
		t.Fatalf("actual native status unavailable: %s", data)
	}
	waitStatus()
	for _, target := range []string{"10.9.0.1:1812", "10.9.0.1:1813"} {
		probe, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		if e = native.ProbeStatus(probe, target, secret); e == nil {
			t.Error("public status unexpectedly enabled")
		}
		cancel()
	}
	bad, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	if e = native.ProbeStatus(bad, "10.9.0.1:18121", []byte(strings.Repeat("x", 40))); e == nil {
		t.Error("wrong health secret accepted")
	}
	cancel()
	expected, e := native.ExpectedReadiness(cfg, certificate.Certificate)
	if e != nil {
		t.Fatal(e)
	}
	expected.Ready = true
	var local *http.Server
	startPolicy := func() {
		t.Helper()
		listener, e := net.Listen("tcp", "10.9.0.1:18122")
		if e != nil {
			t.Fatal(e)
		}
		local = &http.Server{Handler: native.ReadinessHandler(secret, []string{"10.9.0.1"}, func(context.Context) (native.Readiness, error) { return expected, nil }), ReadHeaderTimeout: time.Second}
		go func() { _ = local.Serve(listener) }()
	}
	defer func() {
		if local != nil {
			_ = local.Close()
		}
	}()
	startPolicy()
	backend := &RadiusBackend{caHealth: func(context.Context) error { return nil }, Local: "10.9.0.1", Peer: "10.9.0.2", Secret: secret, Expected: expected, Companions: true}
	// The peer authentication protocol is exercised separately; this test controls
	// only its own local child and checks the real listener/policy ordering.
	backend.status = func(ctx context.Context, address string, key []byte) error {
		if strings.HasPrefix(address, "10.9.0.2") {
			return nil
		}
		return native.ProbeStatus(ctx, address, key)
	}
	backend.readiness = func(ctx context.Context, address string, key []byte, state native.Readiness) error {
		if strings.Contains(address, "10.9.0.2") {
			return nil
		}
		return native.ProbeReadiness(ctx, address, key, state)
	}
	masked := false
	simulateWants := false
	backend.run = func(_ context.Context, path string, args ...string) ([]byte, error) {
		action := strings.Join(args, " ")
		if strings.Contains(action, "--property=LoadState") {
			return []byte("loaded\n"), nil
		}
		if strings.HasPrefix(action, "show ") {
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
		case "stop freeradius.service":
			stop()
		case "restart cloud-8021x.service":
			if simulateWants && !masked {
				return nil, errors.New("daemon Wants could start native before guarded readiness")
			}
			if process != nil {
				t.Error("native process still listening during policy restart")
			}
			_ = local.Close()
			local = nil
			startPolicy()
		case "start freeradius.service":
			if e := native.ProbeReadiness(ctx, "http://10.9.0.1:18122", secret, expected); e != nil {
				return nil, e
			}
			start()
			waitStatus()
		}
		return nil, nil
	}
	if e = backend.Activate(ctx); e != nil {
		t.Fatal(e)
	}
	if e = backend.Healthy(ctx); e != nil {
		t.Fatal(e)
	}
	// Actual certificate reader accepts the protected root:native key and refuses
	// another-reader permissions before any cache adoption or signing.
	if cached, e := ReadNativeServerCache(); e != nil || !bytes.Equal(cached.Key, certificate.Key) {
		t.Fatal("installed leaf cache", e)
	}
	keyPath := filepath.Join(radiusDirectory, "certs/server-key.pem")
	if e = os.Chmod(keyPath, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadNativeServerCache(); e == nil {
		t.Fatal("world-readable private key accepted")
	}
	if e = os.Chmod(keyPath, 0640); e != nil {
		t.Fatal(e)
	}
	units, e := systemd.Render()
	if e != nil {
		t.Fatal(e)
	}
	if e = Write(File{Path: "/etc/sudoers.d/cloud-8021x", Data: units["/etc/sudoers.d/cloud-8021x"], Mode: 0440}); e != nil {
		t.Fatal(e)
	}
	configPath := "/etc/cloud-8021x/config.yaml"
	if e = Write(File{Path: configPath, Data: []byte("known-prior-config"), Mode: 0600}); e != nil {
		t.Fatal(e)
	}
	prior := *backend
	candidate := *backend
	candidate.collectorStart = func(context.Context) error { return errors.New("injected candidate collector failure") }
	attempt, e := BeginTransaction(func(string) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	if e = attempt.CaptureInitialState(ctx, &candidate, &prior); e != nil {
		t.Fatal(e)
	}
	if e = attempt.Prepare(tree, []File{{Path: configPath, Data: []byte("candidate-config"), Mode: 0600}}); e != nil {
		t.Fatal(e)
	}
	simulateWants = true
	if e = attempt.Apply(ctx, &candidate); e == nil {
		t.Fatal("failed activation reported success")
	}
	if attempt.receipt.Phase != "rolled-back" || masked || process == nil {
		t.Fatalf("healthy prior rollback incomplete phase=%s mask=%v", attempt.receipt.Phase, masked)
	}
	if data, e := os.ReadFile(configPath); e != nil || string(data) != "known-prior-config" {
		t.Fatal("prior config not restored", e)
	}
	if e = prior.Healthy(ctx); e != nil {
		t.Fatal("restored actual native/policy readiness", e)
	}
	if e = os.Chown(filepath.Join(radiusDirectory, "certs/server-key.pem"), 0, accounts.NativeGID); e != nil {
		t.Fatal(e)
	}
}
