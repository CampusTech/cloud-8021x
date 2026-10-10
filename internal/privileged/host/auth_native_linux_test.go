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
	startNative := func() {
		t.Helper()
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
		// Green preparation has no retired legacy writer. Its ordinary completed
		// receipt must independently attest the installed native auth module.
		if e = transaction.Apply(ctx, &activationFixture{}); e != nil {
			t.Fatal(e)
		}
		startNative()
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
	g1, g2, g3, g4, g5 := strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 32), strings.Repeat("d", 32), strings.Repeat("e", 32)
	first := activate(g1, nil)
	receiptPath := filepath.Join(transactionRoot, first.Reference, "receipt.json")
	completed, e := os.ReadFile(receiptPath)
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"tampered native hash", "incomplete receipt", "retirement receipt", "null retirement receipt"} {
		t.Run(name, func(t *testing.T) {
			var receipt Receipt
			if e := json.Unmarshal(completed, &receipt); e != nil {
				t.Fatal(e)
			}
			if receipt.Native["mods-enabled/auth_detail"] != first.ModuleSHA256 {
				t.Fatal("native auth module lacks exact independent attestation")
			}
			if name == "tampered native hash" {
				receipt.Native["mods-enabled/auth_detail"] = strings.Repeat("0", 64)
			} else if name == "incomplete receipt" {
				receipt.Phase = "prepared"
			}
			raw, e := json.Marshal(receipt)
			if e != nil {
				t.Fatal(e)
			}
			if strings.Contains(name, "retirement") {
				var fields map[string]json.RawMessage
				if e = json.Unmarshal(raw, &fields); e != nil {
					t.Fatal(e)
				}
				retirement := json.RawMessage(`null`)
				if name == "retirement receipt" {
					retirement, e = json.Marshal(map[string]any{"Transition": strings.Repeat("f", 64), "ReceiptSHA256": strings.Repeat("0", 64), "Native": receipt.Native})
					if e != nil {
						t.Fatal(e)
					}
				}
				fields["writer_retirement"] = retirement
				raw, e = json.Marshal(fields)
				if e != nil {
					t.Fatal(e)
				}
			}
			if e = os.WriteFile(receiptPath, raw, 0600); e != nil {
				t.Fatal(e)
			}
			defer func() {
				if e := os.WriteFile(receiptPath, completed, 0600); e != nil {
					t.Error(e)
				}
			}()
			if _, e = CaptureAuthGeneration(ctx, backend); e == nil {
				t.Fatal("invalid native activation evidence accepted")
			}
		})
	}
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
	// An ordinary restart preserves the module and receipt but changes the
	// actual producer. Renewal may proceed without manufacturing closure.
	stop()
	startNative()
	packet()
	uncertain, e := CaptureAuthGeneration(ctx, backend)
	if e != nil || uncertain != nil {
		t.Fatalf("ordinary restart blocked renewal or invented closure: prior=%+v err=%v", uncertain, e)
	}
	persisted, e := readAuthGeneration(g2)
	if e != nil || persisted.Producer != second.Producer {
		t.Fatal("restart rewrote protected producer attestation", e)
	}
	reader, e = auth.New(auth.Options{Directory: authDirectory, Host: "fixture", ProducerUID: accounts.NativeUID, EventGID: accounts.EventsGID, Store: store})
	if e != nil {
		t.Fatal(e)
	}
	if n, e := reader.Poll(ctx); e != nil || n != 2 {
		t.Fatal("restart logs were not consumed to EOF", n, e)
	}
	stop()
	// Proven stop cannot bypass the same attestation validation used while active.
	stoppedReceipt := filepath.Join(transactionRoot, second.Reference, "receipt.json")
	originalReceipt, e := os.ReadFile(stoppedReceipt)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(stoppedReceipt, []byte("{"), 0600); e != nil {
		t.Fatal(e)
	}
	_, rejected := CaptureAuthGeneration(ctx, backend)
	if e = os.WriteFile(stoppedReceipt, originalReceipt, 0600); e != nil {
		t.Fatal(e)
	}
	if rejected == nil || !strings.Contains(rejected.Error(), "completed native attestation") {
		t.Fatalf("stopped capture bypassed malformed receipt: %v", rejected)
	}
	if prior, e := CaptureAuthGeneration(ctx, backend); e != nil || prior != nil {
		t.Fatalf("proven stopped native blocked renewal or invented closure: prior=%+v err=%v", prior, e)
	}
	third := activate(g3, uncertain)
	if third.ClosedPrevious || third.Previous != "" {
		t.Fatal("renewal manufactured closure for uncertain producer")
	}
	if n, e := reader.Poll(ctx); e != nil || n != 1 {
		t.Fatal("replacement logs were not consumed to EOF", n, e)
	}
	_ = reader.Close()
	secondPath := filepath.Join(authDirectory, "auth-"+g2+"-2026100810.detail")
	thirdPath := filepath.Join(authDirectory, "auth-"+g3+"-2026100810.detail")
	thirdModule, e := os.ReadFile(radiusDirectory + "/mods-enabled/auth_detail")
	if e != nil {
		t.Fatal(e)
	}
	pending := filepath.Join(authDirectory, "auth-"+g1+"-1999010100.detail")
	if e = os.WriteFile(pending, []byte("malformed pending\n\n"), 0640); e != nil {
		t.Fatal(e)
	}
	if e = os.Chown(pending, accounts.NativeUID, accounts.EventsGID); e != nil {
		t.Fatal(e)
	}
	stop()
	result, e := PruneClosedAuthGenerations(ctx, backend, "fixture", g4, g3, accounts, store)
	if e != nil || result.Removed != 2 || result.Retained != 1 {
		t.Fatalf("closed native cleanup=%+v err=%v", result, e)
	}
	if _, e = os.Stat(pending); e != nil {
		t.Fatal("malformed original lost", e)
	}
	for _, path := range []string{secondPath, thirdPath} {
		if _, e = os.Stat(path); e != nil {
			t.Fatal("uncertain or rollback generation removed", path, e)
		}
	}
	activate(g4, third)
	stop()
	fourthModule, e := os.ReadFile(radiusDirectory + "/mods-enabled/auth_detail")
	if e != nil {
		t.Fatal(e)
	}
	// Restore a prior completed auth module while stopped. Its historical
	// closure cannot authorize deleting the currently configured generation.
	if e = os.WriteFile(radiusDirectory+"/mods-enabled/auth_detail", thirdModule, 0600); e != nil {
		t.Fatal(e)
	}
	result, e = PruneClosedAuthGenerations(ctx, backend, "fixture", g5, g4, accounts, store)
	if e != nil || result.Removed != 0 || result.Retained != 1 {
		t.Fatalf("current generation cleanup=%+v err=%v", result, e)
	}
	if _, e = os.Stat(thirdPath); e != nil {
		t.Fatal("current completed generation lost", e)
	}
	if e = os.WriteFile(radiusDirectory+"/mods-enabled/auth_detail", fourthModule, 0600); e != nil {
		t.Fatal(e)
	}
	result, e = PruneClosedAuthGenerations(ctx, backend, "fixture", g5, g4, accounts, store)
	if e != nil || result.Removed != 1 || result.Retained != 1 {
		t.Fatalf("later closed generation cleanup=%+v err=%v", result, e)
	}
	for _, path := range []string{secondPath, pending, filepath.Join(authDirectory, "auth-"+g4+"-2026100810.detail")} {
		if _, e = os.Stat(path); e != nil {
			t.Fatal("uncertain, unconsumed or rollback generation lost", path, e)
		}
	}
	if _, e = os.Stat(firstPath); !os.IsNotExist(e) {
		t.Fatal("old producer generation reopened after distinct activation", e)
	}
}
