package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"
)

func TestVerifyLeafCLIArgsAndFlags(t *testing.T) {
	for _, args := range [][]string{{"radius", "verify-leaf", "/run/radius-verified-leaves/leaf.pem", strings.Repeat("a", 64)}, {"radius", "verify-leaf", "--certificate-file", "/run/radius-verified-leaves/leaf.pem", "--session-token", strings.Repeat("a", 64)}} {
		r := new(recorder)
		if _, err := execute(t, context.Background(), r, args...); err != nil {
			t.Fatal(err)
		}
		if !r.called || r.operation != OperationRadiusVerifyLeaf || r.options.VerifiedLeaf == nil || r.options.VerifiedLeaf.CertificateFile != "/run/radius-verified-leaves/leaf.pem" || r.options.VerifiedLeaf.SessionToken != strings.Repeat("a", 64) {
			t.Fatal("hook input not dispatched")
		}
	}
	for _, args := range [][]string{{"radius", "verify-leaf"}, {"radius", "verify-leaf", "/tmp/x", "bad-token"}, {"radius", "verify-leaf", "--certificate-file", "/tmp/x"}} {
		r := new(recorder)
		if _, err := execute(t, context.Background(), r, args...); err == nil || r.called {
			t.Fatal("invalid hook called service")
		}
	}
}
func TestRuntimeDispatcherServeRejectsMissingRuntimeAccount(t *testing.T) {
	runtime := NewRuntimeServices()
	if err := runtime.Run(context.Background(), OperationServe, configuredFixture(t), RunOptions{}); err == nil || errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}
func TestVerifyLeafDryRunParsesLeafWithoutWriting(t *testing.T) {
	cfg := configuredFixture(t)
	dir := t.TempDir()
	cfg.Backends.RadiusVerifyLeafDir = dir
	cfg.Paths.HandoffDir = filepath.Join(dir, "handoff")
	p := filepath.Join(dir, "leaf.pem")
	_ = os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not X509")}), 0600)
	err := NewRuntimeServices().Run(context.Background(), OperationRadiusVerifyLeaf, cfg, RunOptions{DryRun: true, VerifiedLeaf: &VerifiedLeafOptions{CertificateFile: p, SessionToken: strings.Repeat("a", 64)}})
	if err == nil {
		t.Fatal("unparsed certificate accepted")
	}
	if _, err := os.Stat(cfg.Paths.HandoffDir); !os.IsNotExist(err) {
		t.Fatal("dry-run mutated handoff")
	}
}

func configuredFixture(t *testing.T) config.Config {
	t.Helper()
	cfg, err := config.Decode(strings.NewReader(fixture))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
func TestPrivilegedVerifyLeafRejectsAlternateConfigBeforeAnyControlledPathReadOrMutation(t *testing.T) {
	cfg := configuredFixture(t)
	dir := t.TempDir()
	cfg.Backends.RadiusVerifyLeafDir = dir
	cfg.Paths.HandoffDir = filepath.Join(dir, "handoff")
	cfg.Paths.DowngradeGuardFile = filepath.Join(dir, "guard")
	err := NewRuntimeServices().Run(context.Background(), OperationRadiusVerifyLeaf, cfg, RunOptions{ConfigFile: filepath.Join(dir, "attacker.yaml"), VerifiedLeaf: &VerifiedLeafOptions{CertificateFile: filepath.Join(dir, "does-not-exist"), SessionToken: strings.Repeat("a", 64)}})
	if err == nil || strings.Contains(err.Error(), "leaf unavailable") {
		t.Fatal("privileged path opened before trust gate", err)
	}
	for _, path := range []string{cfg.Paths.HandoffDir, cfg.Paths.DowngradeGuardFile} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("untrusted config mutated state", path)
		}
	}
}
func TestProtectedHookConfigurationRejectsSymlinkAndWritableOrUnprivilegedOwner(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config")
	_ = os.WriteFile(p, []byte(fixture), 0666)
	_ = os.Chmod(p, 0666)
	if _, err := readProtectedHookConfig(p); err == nil {
		t.Fatal("writable root hook config")
	}
	link := filepath.Join(dir, "symlink")
	_ = os.Symlink(p, link)
	if _, err := readProtectedHookConfig(link); err == nil {
		t.Fatal("symlink hook config")
	}
	if os.Geteuid() != 0 {
		_ = os.Chmod(p, 0600)
		if _, err := readProtectedHookConfig(p); err == nil {
			t.Fatal("attacker-owned root hook config")
		}
	}
}
func TestActualCLIDispatchValidCertificateDryRun(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root verify-leaf, including dry-run, is restricted to the installed protected configuration; non-root CLI planning is tested here")
	}
	leaf, _, _ := makeRuntimeCertificate(t)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	leafPath := filepath.Join(dir, "leaf.pem")
	_ = os.WriteFile(leafPath, leaf, 0600)
	data := fixture + "\nbackends:\n  radius_verify_leaf_dir: " + dir + "\npaths:\n  handoff_dir: " + filepath.Join(dir, "handoff") + "\n  downgrade_guard_file: " + filepath.Join(dir, "guard") + "\n"
	_ = os.WriteFile(cfgPath, []byte(data), 0600)
	cmd := NewCommand(Options{Services: NewRuntimeServices()})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--config", cfgPath, "--dry-run", "radius", "verify-leaf", leafPath, strings.Repeat("a", 64)})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "no handoff or guard written") {
		t.Fatal(out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "handoff")); !os.IsNotExist(err) {
		t.Fatal("CLI dry run wrote handoff")
	}
}
func makeRuntimeCertificate(t *testing.T) ([]byte, []byte, time.Time) {
	t.Helper()
	now := time.Now()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Client"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil, now
}

func TestRootDryRunDoesNotBypassFixedConfiguration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root helper process")
	}
	cfg := configuredFixture(t)
	err := NewRuntimeServices().Run(context.Background(), OperationRadiusVerifyLeaf, cfg, RunOptions{DryRun: true, ConfigFile: "/tmp/attacker-config", VerifiedLeaf: &VerifiedLeafOptions{CertificateFile: "/run/radius-verified-leaves/missing", SessionToken: strings.Repeat("a", 64)}})
	if err == nil || !strings.Contains(err.Error(), "fixed protected") {
		t.Fatal("root dry-run bypass", err)
	}
}
func TestCobraRootHookRejectsAlternateConfigBeforeInitialLoad(t *testing.T) {
	r := new(recorder)
	cmd := NewCommand(Options{Services: r, ProcessUID: func() int { return 0 }})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--config", filepath.Join(t.TempDir(), "missing-root-only-file"), "--dry-run", "radius", "verify-leaf", "/run/radius-verified-leaves/leaf.pem", strings.Repeat("a", 64)})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "fixed protected") || strings.Contains(err.Error(), "open configuration") || r.called {
		t.Fatal("Cobra opened attacker-selected config before privilege gate", err)
	}
}

func TestVerifyLeafRejectsReplacedDirectoryComponentBeforeRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("unprivileged dry-run exercises the same descriptor confinement without installed root configuration")
	}
	for _, component := range []string{"final-directory", "ancestor"} {
		t.Run(component, func(t *testing.T) {
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(base, "outside")
			if err := os.Mkdir(outside, 0700); err != nil {
				t.Fatal(err)
			}
			leaf, _, _ := makeRuntimeCertificate(t)
			if err := os.WriteFile(filepath.Join(outside, "leaf.pem"), leaf, 0600); err != nil {
				t.Fatal(err)
			}
			fixed := filepath.Join(base, "verified-leaves")
			if component == "final-directory" {
				if err := os.Symlink(outside, fixed); err != nil {
					t.Fatal(err)
				}
			} else {
				ancestor := filepath.Join(base, "replaced-parent")
				if err := os.Symlink(base, ancestor); err != nil {
					t.Fatal(err)
				}
				fixed = filepath.Join(ancestor, "outside")
			}
			cfg := configuredFixture(t)
			cfg.Backends.RadiusVerifyLeafDir = fixed
			cfg.Paths.HandoffDir = filepath.Join(base, "handoff")
			cfg.Paths.DowngradeGuardFile = filepath.Join(base, "guard")
			err = NewRuntimeServices().Run(context.Background(), OperationRadiusVerifyLeaf, cfg, RunOptions{DryRun: true, VerifiedLeaf: &VerifiedLeafOptions{CertificateFile: filepath.Join(fixed, "leaf.pem"), SessionToken: strings.Repeat("a", 64)}})
			if err == nil {
				t.Fatal("helper followed replaced directory component and accepted outside certificate")
			}
			for _, p := range []string{cfg.Paths.HandoffDir, cfg.Paths.DowngradeGuardFile} {
				if _, err := os.Lstat(p); !os.IsNotExist(err) {
					t.Fatal("rejected source mutated state", p)
				}
			}
		})
	}
}
func TestVerifyLeafRejectsHardlinkedInputBeforeRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("unprivileged dry-run does not require installed root configuration")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "verified-leaves")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	leaf, _, _ := makeRuntimeCertificate(t)
	original := filepath.Join(base, "outside-leaf.pem")
	if err := os.WriteFile(original, leaf, 0600); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(dir, "leaf.pem")
	if err := os.Link(original, inside); err != nil {
		t.Fatal(err)
	}
	cfg := configuredFixture(t)
	cfg.Backends.RadiusVerifyLeafDir = dir
	cfg.Paths.HandoffDir = filepath.Join(base, "handoff")
	cfg.Paths.DowngradeGuardFile = filepath.Join(base, "guard")
	if err := NewRuntimeServices().Run(context.Background(), OperationRadiusVerifyLeaf, cfg, RunOptions{DryRun: true, VerifiedLeaf: &VerifiedLeafOptions{CertificateFile: inside, SessionToken: strings.Repeat("a", 64)}}); err == nil {
		t.Fatal("helper accepted hardlinked public leaf outside the approved directory")
	}
}
