package host

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/freeradius/native"
	"github.com/CampusTech/cloud-8021x/internal/adapters/stepca"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/events/auth"
)

type nativeAuthCursorFixture struct {
	cursors map[string]string
	events  int
}

func (s *nativeAuthCursorFixture) Cursor(_ context.Context, source string) (string, error) {
	return s.cursors[source], nil
}
func (s *nativeAuthCursorFixture) AuthEvent(_ context.Context, source, expected, next, _ string, _ json.RawMessage) error {
	if s.cursors[source] != expected {
		return fmt.Errorf("cursor mismatch")
	}
	s.cursors[source] = next
	s.events++
	return nil
}
func (s *nativeAuthCursorFixture) AuthCursors(_ context.Context, sources []string) (map[string]string, error) {
	out := map[string]string{}
	for _, source := range sources {
		out[source] = s.cursors[source]
	}
	return out, nil
}

// Actual packaged native detail producer, cached descriptors and controlled wall
// clock rollback. systemctl observations are injected around the real PID; full
// systemd dependency behavior remains the separate Linux service acceptance gate.
func TestInstalledAuthGenerationRetentionAndClockRollback(t *testing.T) {
	if os.Getenv("C8021X_AUTH_FIXTURE") != "task9" {
		t.Skip("owned actual native auth fixture required")
	}
	faketimeLibrary := map[string]string{
		"arm64": "/usr/lib/aarch64-linux-gnu/faketime/libfaketime.so.1",
		"amd64": "/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1",
	}[runtime.GOARCH]
	if faketimeLibrary == "" {
		t.Fatal("unsupported native fixture architecture")
	}
	if _, err := os.Stat(faketimeLibrary); err != nil {
		t.Fatal("pinned architecture-specific faketime fixture unavailable", err)
	}
	ctx := context.Background()
	run := func(path string, args ...string) {
		t.Helper()
		if out, e := exec.Command(path, args...).CombinedOutput(); e != nil {
			t.Fatalf("%s: %v %s", path, e, out)
		}
	}
	run("/usr/sbin/useradd", "--system", "--no-create-home", "dd-agent")
	accounts, e := EnsureAccounts(ctx)
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := config.Load("/fixture/config.yaml")
	if e != nil {
		t.Fatal(e)
	}
	cfg.Network.Discovery.Enabled = false
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
	const clockFile = "/run/task9-auth-clock"
	clockAt := func(value string) {
		t.Helper()
		if e = os.WriteFile(clockFile, []byte(value), 0644); e != nil {
			t.Fatal(e)
		}
	}
	clockAt("2026-10-08 10:00:00")
	var process *exec.Cmd
	stop := func() {
		if process != nil {
			_ = process.Process.Kill()
			_ = process.Wait()
			process = nil
		}
	}
	defer stop()
	backend := &RadiusBackend{run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if len(args) == 4 && args[2] == "--property=MainPID" {
			if process == nil {
				return []byte("0\n"), nil
			}
			return []byte(strconv.Itoa(process.Process.Pid) + "\n"), nil
		}
		if process == nil {
			return []byte("ActiveState=inactive\nSubState=dead\nMainPID=0\n"), nil
		}
		return []byte(fmt.Sprintf("ActiveState=active\nSubState=running\nMainPID=%d\n", process.Process.Pid)), nil
	}}
	packet := func() {
		t.Helper()
		command := exec.Command("/usr/bin/radclient", "-r", "1", "-t", "1", "127.0.0.1:1812", "auth", "fixture")
		command.Stdin = strings.NewReader("User-Name = \"fixture\"\nMessage-Authenticator = 0x00\n")
		if out, e := command.CombinedOutput(); e != nil {
			data, _ := os.ReadFile("/var/log/freeradius/radius.log")
			t.Fatalf("native auth packet: %v %s log=%s", e, out, data)
		}
	}
	activate := func(generation string, prior *AuthGeneration) *AuthGeneration {
		t.Helper()
		tree, e := native.RenderWithSecrets(cfg, generation, secrets)
		if e != nil {
			t.Fatal(e)
		}
		tree["certs/server-cert.pem"] = certificate.Certificate
		tree["certs/server-key.pem"] = certificate.Key
		tree["clients.conf"] = []byte("client fixture {\n ipaddr = 127.0.0.1\n secret = fixture\n require_message_authenticator = yes\n}\n")
		tree["sites-enabled/default"] = []byte("server default {\n listen {\n type = auth\n ipaddr = 127.0.0.1\n port = 1812\n }\n authorize {\n update control { Auth-Type := Accept }\n }\n post-auth {\n update reply { C8021X-Receipt := \"%l\" }\n auth_detail\n }\n}\n")
		delete(tree, "sites-enabled/health")
		delete(tree, "sites-enabled/certificate")
		delete(tree, "sites-enabled/buffered")
		delete(tree, "mods-enabled/eap")
		delete(tree, "mods-enabled/rest")
		delete(tree, "mods-enabled/sql")
		transaction, e := PrepareTransaction(tree, nil, func(string) error { return nil })
		if e != nil {
			t.Fatal(e)
		}
		transaction.receipt.WriterRetirement = &writerRetirement{Native: map[string]string{}}
		for name, raw := range tree {
			transaction.receipt.WriterRetirement.Native[name] = digestBytes(raw)
		}
		if e = transaction.Apply(ctx, &activationFixture{}); e != nil {
			t.Fatal(e)
		}
		run("/usr/sbin/freeradius", "-XC")
		log, e := os.OpenFile("/run/task9-auth-native.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if e != nil {
			t.Fatal(e)
		}
		process = exec.Command("/usr/sbin/freeradius", "-d", radiusDirectory, "-f")
		process.Stdout = log
		process.Stderr = log
		process.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LD_PRELOAD=" + faketimeLibrary, "FAKETIME_TIMESTAMP_FILE=" + clockFile, "FAKETIME_NO_CACHE=1", "FAKETIME_DONT_FAKE_MONOTONIC=1"}
		if e = process.Start(); e != nil {
			t.Fatal(e)
		}
		_ = log.Close()
		time.Sleep(150 * time.Millisecond)
		packet()
		if e = CompleteAuthGeneration(ctx, backend, transaction.Reference(), generation, prior); e != nil {
			args, readErr := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", process.Process.Pid))
			t.Fatalf("actual native producer argv=%q read=%v: %v", args, readErr, e)
		}
		observed, e := CaptureAuthGeneration(ctx, backend)
		if e != nil {
			t.Fatal(e)
		}
		return observed
	}
	g1, g2, g3 := strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 32)
	first := activate(g1, nil)
	firstPath := filepath.Join(authDirectory, "auth-"+g1+"-2026100810.detail")
	info, e := os.Stat(firstPath)
	if e != nil {
		t.Fatal(e)
	}
	firstSize := info.Size()
	fds, e := os.ReadDir(fmt.Sprintf("/proc/%d/fd", process.Process.Pid))
	if e != nil {
		t.Fatal(e)
	}
	cached := false
	for _, fd := range fds {
		target, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", process.Process.Pid, fd.Name()))
		if target == firstPath {
			cached = true
		}
	}
	if !cached {
		t.Fatal("actual native detail descriptor was not retained")
	}
	clockAt("2026-10-08 12:00:00")
	packet()
	clockAt("2026-10-08 10:00:00")
	packet()
	info, e = os.Stat(firstPath)
	if e != nil || info.Size() <= firstSize {
		t.Fatal("clock rollback did not reopen original-hour native filename", e)
	}
	store := &nativeAuthCursorFixture{cursors: map[string]string{}}
	reader, e := auth.New(auth.Options{Directory: authDirectory, Host: "fixture", ProducerUID: accounts.NativeUID, EventGID: accounts.EventsGID, Store: store})
	if e != nil {
		t.Fatal(e)
	}
	if n, e := reader.Poll(ctx); e != nil || n != 3 {
		t.Fatal("actual final native detail parsing", n, e)
	}
	_ = reader.Close()
	if _, e = PruneClosedAuthGenerations(ctx, backend, "fixture", g3, g2, accounts, store); e == nil {
		t.Fatal("active native cleanup allowed")
	}
	stop()
	second := activate(g2, first)
	if second.Generation == first.Generation || second.Producer == first.Producer {
		t.Fatal("replacement generation did not bind new real producer")
	}
	pending := filepath.Join(authDirectory, "auth-"+g1+"-1999010100.detail")
	if e = os.WriteFile(pending, []byte("malformed pending\n\n"), 0640); e != nil {
		t.Fatal(e)
	}
	if e = os.Chown(pending, accounts.NativeUID, accounts.EventsGID); e != nil {
		t.Fatal(e)
	}
	stop()
	result, e := PruneClosedAuthGenerations(ctx, backend, "fixture", g3, g2, accounts, store)
	if e != nil || result.Removed != 2 || result.Retained != 1 {
		t.Fatalf("closed native cleanup=%+v err=%v", result, e)
	}
	if _, e = os.Stat(pending); e != nil {
		t.Fatal("malformed original lost", e)
	}
	activate(g3, second)
	if _, e = os.Stat(firstPath); !os.IsNotExist(e) {
		t.Fatal("old producer generation reopened after distinct activation", e)
	}
}
