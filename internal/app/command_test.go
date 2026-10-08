package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/config"
)

const fixture = `schema_version: 1
debug: false
listeners:
  policy:
    token: {file: /run/policy-token}
policy:
  class_signing_key: {file: /run/class-key}
database:
  runtime_dsn: {file: /run/cloud-8021x/runtime-dsn}
  migration_dsn: {file: /run/cloud-8021x/migration-dsn}
  native_writer_dsn: {file: /run/cloud-8021x/native-dsn}
  ca_file: /etc/cloud-8021x/postgres-ca.pem
`

func execute(t *testing.T, ctx context.Context, services Services, args ...string) (string, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(fixture), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := NewCommand(Options{Version: "test-version", Services: services})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(append([]string{"--config", path}, args...))
	err := cmd.ExecuteContext(ctx)
	return out.String(), err
}

type recorder struct {
	called    bool
	operation Operation
	config    config.Config
	options   RunOptions
}

func (r *recorder) Run(ctx context.Context, op Operation, cfg config.Config, options RunOptions) error {
	r.called = true
	r.operation = op
	r.config = cfg
	r.options = options
	return ctx.Err()
}

func TestConfigValidateAndVersion(t *testing.T) {
	out, err := execute(t, context.Background(), nil, "config", "validate")
	if err != nil || !strings.Contains(out, "valid") {
		t.Fatalf("validate output=%q error=%v", out, err)
	}
	out, err = execute(t, context.Background(), nil, "version")
	if err != nil || !strings.Contains(out, "test-version") {
		t.Fatalf("version output=%q error=%v", out, err)
	}
}

func TestCLIOverridesAndDryRun(t *testing.T) {
	r := new(recorder)
	_, err := execute(t, context.Background(), r, "--debug", "--dry-run", "--policy-address", "127.0.0.1:9090", "serve")
	if err != nil {
		t.Fatal(err)
	}
	if !r.called || r.operation != OperationServe || !r.options.Debug || !r.options.DryRun || r.config.Listeners.Policy.Address != "127.0.0.1:9090" {
		t.Fatalf("missing overrides: %+v", r)
	}
	for _, args := range [][]string{{"serve"}, {"--dry-run", "inventory", "sync"}, {"radius", "verify-leaf"}, {"bootstrap"}} {
		_, err = execute(t, context.Background(), nil, args...)
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("unfinished command must fail explicitly: %v", err)
		}
	}
}

func TestCancellationNeverCallsServices(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := new(recorder)
	_, err := execute(t, ctx, r, "serve")
	if !errors.Is(err, context.Canceled) || r.called {
		t.Fatalf("cancellation err=%v called=%v", err, r.called)
	}
}

func TestUnifiedChallengeRequiresFileAndRespectsDryRun(t *testing.T) {
	t.Setenv("SCEP_CHALLENGE_SIGNING_KEY", strings.Repeat("s", 32))
	output := filepath.Join(t.TempDir(), "challenge")
	_, err := execute(t, context.Background(), nil, "scep-challenge", "--identity", "device", "--provisioner", "wifi-scep", "--out", output)
	if err == nil {
		t.Fatal("unified executable must not read legacy environment secrets")
	}
	keyFile := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyFile, []byte(strings.Repeat("k", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := execute(t, context.Background(), nil, "--dry-run", "scep-challenge", "--identity", "device", "--provisioner", "wifi-scep", "--signing-key-file", keyFile, "--out", output)
	if err != nil || !strings.Contains(out, "no challenge written") {
		t.Fatalf("dry run=%q err=%v", out, err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("dry run created token")
	}
}
