package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/migration"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
	"github.com/jackc/pgx/v5"
	"gopkg.in/yaml.v3"
)

// Runs the complete protected command, including fixed config/credential reads,
// root filesystem receipts, the real PG gate, import and local publication.
// Installation and initial writer-fence evidence are injected fixture setup.
func TestInstalledProtectedMigrationRepeatLeavesMaintenanceUsable(t *testing.T) {
	if os.Getenv("C8021X_DAEMON_FIXTURE") != "task9" {
		t.Skip("owned Linux PG fixture required")
	}
	ctx := context.Background()
	write := func(path string, data []byte) {
		t.Helper()
		if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(path, data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	accounts, e := host.EnsureAccounts(ctx)
	if e != nil {
		t.Fatal(e)
	}
	cfg := configuredFixture(t)
	cfg.InstanceID = "radius-primary"
	cfg.StateTransition = strings.Repeat("c", 64)
	cfg.Database.CAFile = os.Getenv("C8021X_PG_TEST_CA")
	cfg.Policy.ClassSigningKey.File = "/run/cloud-8021x/credentials/class-key"
	cfg.Database.MigrationDSN.File = "/run/cloud-8021x-root/migration-dsn"
	cfg.Bootstrap.Secrets = []config.BootstrapSecret{{File: cfg.Policy.ClassSigningKey.File, Owner: "runtime"}, {File: cfg.Database.MigrationDSN.File, Owner: "root"}}
	rawConfig, e := yaml.Marshal(cfg)
	if e != nil {
		t.Fatal(e)
	}
	write(privilegedConfigFile, rawConfig)
	cfg, e = readProtectedSourceConfig()
	if e != nil {
		t.Fatal(e)
	}
	if e = cfg.Validate(); e != nil {
		t.Fatal(e)
	}
	node, hash, e := transitionBinding(cfg)
	if e != nil {
		t.Fatal(e)
	}
	// Exact installed-generation evidence, with a private committed credential set.
	binary := []byte("owned fixture executable identity")
	native := []byte("owned fixture native identity")
	write("/usr/local/bin/cloud-8021x", binary)
	write("/etc/freeradius/3.0/radiusd.conf", native)
	ref := strings.Repeat("a", 32)
	layout := bootCredentialLayout(cfg, accounts)
	for i := range layout {
		layout[i].Data = []byte("fixture-only")
		if layout[i].Path == cfg.Policy.ClassSigningKey.File {
			layout[i].Data = bytes.Repeat([]byte("k"), 32)
		}
		if layout[i].Path == cfg.Database.MigrationDSN.File {
			layout[i].Data = []byte(os.Getenv("C8021X_PG_TEST_DSN"))
		}
	}
	cache, _ := json.Marshal(map[string]any{"reference": ref, "bindings": map[string]string{"/usr/local/bin/cloud-8021x": stateDigest(binary), privilegedConfigFile: stateDigest(rawConfig), "/etc/freeradius/3.0/radiusd.conf": stateDigest(native)}, "files": layout})
	write("/var/lib/cloud-8021x-bootstrap/active-credentials.json", cache)
	generation, _ := json.Marshal(map[string]string{"Reference": ref, "ApplicationSHA256": stateDigest(binary), "ConfigSHA256": stateDigest(rawConfig)})
	write("/var/lib/cloud-8021x-bootstrap/current.json", generation)
	policy := json.RawMessage(`{"version":2,"updated_at":1791453600.123456789,"identities":{},"certificates":{},"hardware_serials":{}}`)
	if e = host.Write(host.File{Path: "/var/lib/cloud-8021x/inventory.json", Data: policy, UID: accounts.RuntimeUID, GID: accounts.RuntimeGID, Mode: 0644}); e != nil {
		t.Fatal(e)
	}
	bundle := migration.Bundle{Version: 1, Node: node, Policy: policy, ClassKeySHA256: stateDigest(bytes.Repeat([]byte("k"), 32)), UsageAbsent: true, SQL: migration.LegacySQL{Status: "absent"}}
	raw, _ := json.Marshal(bundle)
	dir := "/var/lib/cloud-8021x-bootstrap/writers/" + cfg.StateTransition
	write(filepath.Join(dir, "bundle.json"), raw)
	store, e := postgres.NewMigration(ctx, os.Getenv("C8021X_PG_TEST_DSN"), cfg.Database)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	if e = store.Migrate(ctx, postgres.Roles{Runtime: "app_runtime", Native: "app_native"}); e != nil {
		t.Fatal(e)
	}
	gate := postgres.MaintenanceGate{Store: store}
	for _, n := range []string{"radius-primary", "radius-secondary"} {
		if e = gate.With(ctx, "fixture-fence", func(ctx context.Context) error {
			return store.RecordWriterFence(ctx, cfg.StateTransition, n, hash, hash)
		}); e != nil {
			t.Fatal(e)
		}
	}
	inspectCfg, e := pgx.ParseConfig(os.Getenv("C8021X_PG_TEST_DSN"))
	if e != nil {
		t.Fatal(e)
	}
	ca, e := os.ReadFile(cfg.Database.CAFile)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	inspectCfg.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "localhost"}
	inspectCfg.Fallbacks = nil
	inspect, e := pgx.ConnectConfig(ctx, inspectCfg)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = inspect.Close(ctx) }()
	count := func() int {
		t.Helper()
		var n int
		if e := inspect.QueryRow(ctx, "SELECT count(*) FROM bootstrap_private.maintenance").Scan(&n); e != nil {
			t.Fatal(e)
		}
		return n
	}
	var first, second bytes.Buffer
	options := RunOptions{ConfigFile: privilegedConfigFile, Output: &first}
	if e = protectedStateMigrate(ctx, cfg, options); e != nil {
		t.Fatal("first complete protected migration", e)
	}
	before := count()
	original, e := os.ReadFile(filepath.Join(dir, "publication-original.json"))
	if e != nil {
		t.Fatal(e)
	}
	options.Output = &second
	if e = protectedStateMigrate(ctx, cfg, options); e != nil {
		t.Error("duplicate complete protected migration", e)
	}
	if after := count(); after != before {
		t.Errorf("repeat created maintenance row: before=%d after=%d", before, after)
	}
	if first.String() != second.String() {
		t.Errorf("repeat changed original result: first=%s second=%s", first.String(), second.String())
	}
	retained, e := os.ReadFile(filepath.Join(dir, "publication-original.json"))
	if e != nil || !bytes.Equal(original, retained) {
		t.Fatal("original publication receipt changed", e)
	}
	if e = gate.With(ctx, "unrelated-source-maintenance", func(context.Context) error { return nil }); e != nil {
		t.Fatal("repeat blocked unrelated maintenance", e)
	}
	// A completed receipt alone is insufficient: every immutable local artifact
	// and the exact successful SQL attempt/import/publication must still agree.
	for _, name := range []string{"publication-original.json", "publication-complete.json", "published-bundle.json"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			saved, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
			before := count()
			if err = protectedStateMigrate(ctx, cfg, options); err == nil {
				t.Fatal("changed original artifact accepted")
			}
			if count() != before {
				t.Fatal("changed artifact started a new attempt")
			}
			if err = os.WriteFile(path, saved, 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
	completePath := filepath.Join(dir, "publication-complete.json")
	saved, e := os.ReadFile(completePath)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(completePath); e != nil {
		t.Fatal(e)
	}
	before = count()
	if e = protectedStateMigrate(ctx, cfg, options); e == nil {
		t.Fatal("incomplete original accepted as complete")
	}
	if count() != before {
		t.Fatal("incomplete original started new attempt")
	}
	write(completePath, saved)
	var result struct {
		Attempt int64 `json:"attempt"`
	}
	if e = json.Unmarshal(first.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	for _, change := range []struct {
		name, mutate, restore string
		args                  []any
	}{
		{"import-marker", "UPDATE ledger.import_markers SET checksum='changed' WHERE id=$1", "UPDATE ledger.import_markers SET checksum=$2 WHERE id=$1", []any{"state:" + cfg.StateTransition + ":" + node, stateDigest(raw)}},
		{"publication-ack", "UPDATE bootstrap_private.legacy_bundles SET published=false WHERE transition=$1", "UPDATE bootstrap_private.legacy_bundles SET published=true WHERE transition=$1", []any{cfg.StateTransition}},
		{"original-attempt", "UPDATE bootstrap_private.maintenance SET outcome='uncertain' WHERE id=$1", "UPDATE bootstrap_private.maintenance SET outcome='complete' WHERE id=$1", []any{result.Attempt}},
	} {
		t.Run(change.name, func(t *testing.T) {
			if _, err := inspect.Exec(ctx, change.mutate, change.args[0]); err != nil {
				t.Fatal(err)
			}
			before := count()
			if err := protectedStateMigrate(ctx, cfg, options); err == nil {
				t.Fatal("uncommitted completion accepted")
			}
			if count() != before {
				t.Fatal("uncommitted completion started new attempt")
			}
			if _, err := inspect.Exec(ctx, change.restore, change.args...); err != nil {
				t.Fatal(err)
			}
		})
	}
	if e = gate.With(ctx, "unrelated-certificate-maintenance", func(context.Context) error { return nil }); e != nil {
		t.Fatal("strict repeat checks blocked unrelated gate", e)
	}

}
