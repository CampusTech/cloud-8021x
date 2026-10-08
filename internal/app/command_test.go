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
	"github.com/sirupsen/logrus"
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
	cmd := NewCommand(Options{Version: "test-version", Services: services, ProcessUID: func() int { return 501 }})
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
	for _, args := range [][]string{{"serve"}, {"--dry-run", "inventory", "sync"}, {"bootstrap"}} {
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

func TestPolicyAddressOverrideRepairsConfiguredAddress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	invalid := strings.Replace(fixture, "  policy:\n", "  policy:\n    address: 0.0.0.0:9080\n", 1)
	if err := os.WriteFile(path, []byte(invalid), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(path); err == nil {
		t.Fatal("default config.Load must still validate")
	}
	r := new(recorder)
	cmd := NewCommand(Options{Services: r})
	cmd.SetArgs([]string{"--config", path, "--policy-address", "127.0.0.1:9080", "serve"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("safe effective override rejected: %v", err)
	}
	if !r.called || r.config.Listeners.Policy.Address != "127.0.0.1:9080" {
		t.Fatal("service did not receive validated effective config")
	}
}

func TestUnifiedChallengeUsesEffectiveDebugAndInjectedLogger(t *testing.T) {
	for _, tc := range []struct {
		name      string
		yamlDebug bool
		flags     []string
		wantLog   bool
	}{
		{"yaml debug", true, nil, true},
		{"flag enables", false, []string{"--debug"}, true},
		{"flag disables", true, []string{"--debug=false"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			key := filepath.Join(dir, "key")
			output := filepath.Join(dir, "challenge")
			data := fixture
			if tc.yamlDebug {
				data = strings.Replace(data, "debug: false", "debug: true", 1)
			}
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(key, []byte(strings.Repeat("k", 32)), 0600); err != nil {
				t.Fatal(err)
			}
			logger := logrus.New()
			logger.SetFormatter(&logrus.JSONFormatter{})
			hook := new(logCapture)
			logger.AddHook(hook)
			cmd := NewCommand(Options{Logger: logger})
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			args := append([]string{"--config", path}, tc.flags...)
			cmd.SetArgs(append(args, "scep-challenge", "--identity", "device", "--provisioner", "wifi-scep", "--signing-key-file", key, "--out", output))
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			if (len(hook.entries) > 0) != tc.wantLog {
				t.Fatalf("injected logger entries=%d wantLog=%v", len(hook.entries), tc.wantLog)
			}
			if tc.wantLog && (hook.entries[0].Message != "SCEP challenge written" || hook.entries[0].Data["provisioner"] != "wifi-scep") {
				t.Fatalf("missing issuance metadata: %+v", hook.entries)
			}
			if strings.Contains(out.String(), strings.Repeat("k", 32)) {
				t.Fatal("secret exposed in debug output")
			}
		})
	}
}

type logCapture struct{ entries []*logrus.Entry }

func (*logCapture) Levels() []logrus.Level { return logrus.AllLevels }
func (h *logCapture) Fire(e *logrus.Entry) error {
	h.entries = append(h.entries, e.Dup())
	h.entries[len(h.entries)-1].Message = e.Message
	return nil
}

func TestUnifiedChallengeHelpDoesNotOfferLegacyEnvironmentFallback(t *testing.T) {
	cmd := NewCommand(Options{})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"scep-challenge", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "SCEP_CHALLENGE_SIGNING_KEY") {
		t.Fatal("unified help offers unsupported environment fallback")
	}
	legacy := NewCompatibilityCommand("test")
	out.Reset()
	legacy.SetOut(&out)
	legacy.SetArgs([]string{"scep-challenge", "--help"})
	if err := legacy.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "SCEP_CHALLENGE_SIGNING_KEY") {
		t.Fatal("lost legacy environment help")
	}
}
