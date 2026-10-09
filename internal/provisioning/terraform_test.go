package provisioning

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
	"github.com/jackc/pgx/v5"
)

func TestTerraformPrivateRunnerLeastRoles(t *testing.T) { testTerraformPrivateRunner(t, "") }
func TestTerraformGreenPrivateRunnerPreservesBlue(t *testing.T) {
	testTerraformPrivateRunner(t, "green-test")
}
func testTerraformPrivateRunner(t *testing.T, deployment string) {
	database, roles, identityErr := (Config{DeploymentID: deployment}).applicationIdentity()
	if identityErr != nil {
		t.Fatal(identityErr)
	}

	dsn := os.Getenv("C8021X_PG_TEST_DSN")
	if dsn == "" {
		t.Skip("owned PostgreSQL TLS fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	p, e := pgx.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	p.Database = "postgres"
	p.Fallbacks = nil
	p.TLSConfig, e = postgres.VerifiedTLSConfig(config.Database{Name: database, TLSMode: "verify-full", CAFile: os.Getenv("C8021X_PG_TEST_CA")}, p.Host)
	if e != nil {
		t.Fatal(e)
	}
	conn, e := pgx.ConnectConfig(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	// Model Cloud SQL's administrator attributes, not a PostgreSQL SUPERUSER.
	for _, q := range []string{"CREATE ROLE provisioning_admin LOGIN PASSWORD 'disposable-admin' NOSUPERUSER CREATEDB CREATEROLE", "CREATE ROLE stepca LOGIN PASSWORD 'disposable-ca'", "CREATE DATABASE stepca OWNER provisioning_admin", "CREATE DATABASE stepca_rsa OWNER provisioning_admin", "REVOKE ALL ON DATABASE stepca,stepca_rsa FROM PUBLIC", "GRANT CONNECT,TEMPORARY ON DATABASE stepca,stepca_rsa TO stepca"} {
		if _, e = conn.Exec(ctx, q); e != nil {
			t.Fatal(e)
		}
	}
	defer func() {
		for _, q := range []string{"DROP DATABASE IF EXISTS " + database + " WITH (FORCE)", "DROP DATABASE IF EXISTS stepca WITH (FORCE)", "DROP DATABASE IF EXISTS stepca_rsa WITH (FORCE)", "DROP ROLE IF EXISTS " + strings.Join(roles[:], ","), "DROP ROLE IF EXISTS stepca,provisioning_admin"} {
			_, _ = conn.Exec(context.Background(), q)
		}
		if deployment == "" {
			_, _ = conn.Exec(context.Background(), "CREATE DATABASE cloud8021x")
		}
	}()

	// The fixture starts with an empty application DB for storage tests; this test
	// owns this isolated container and recreates that empty DB through Terraform.
	if deployment == "" {
		if _, e = conn.Exec(ctx, "DROP DATABASE cloud8021x WITH (FORCE)"); e != nil {
			t.Fatal(e)
		}
	} else {
		// Preserve an existing application database and its bytes throughout provisioning.
		blueConfig := p.Copy()
		blueConfig.Database = "cloud8021x"
		blue, err := pgx.ConnectConfig(ctx, blueConfig)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = blue.Close(context.Background()) }()
		if _, err = blue.Exec(ctx, "CREATE TABLE IF NOT EXISTS untouched_accounting(value text); INSERT INTO untouched_accounting VALUES ('original-accounting-epoch')"); err != nil {
			t.Fatal(err)
		}
		defer func() {
			var value string
			if err := blue.QueryRow(context.Background(), "SELECT value FROM untouched_accounting LIMIT 1").Scan(&value); err != nil || value != "original-accounting-epoch" {
				t.Errorf("blue historical data changed: %v", err)
			}
		}()
	}
	temp := t.TempDir()
	tool := filepath.Join(temp, "cloud8021x-postgres-admin")
	build := exec.CommandContext(ctx, "go", "build", "-o", tool, "./tools/postgres-admin")
	build.Dir = "../.."
	if out, e := build.CombinedOutput(); e != nil {
		t.Fatalf("admin tool build: %v %s", e, out)
	}
	entries, e := os.ReadDir("../../terraform/postgres")
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tf") || entry.Name() == ".terraform.lock.hcl" {
			data, e := os.ReadFile(filepath.Join("../../terraform/postgres", entry.Name()))
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(temp, entry.Name()), data, 0600); e != nil {
				t.Fatal(e)
			}
		}
	}
	acl := map[string]DatabaseACL{}
	access := map[string][]Access{}
	for _, name := range []string{"stepca", "stepca_rsa"} {
		acl[name], e = readCA(ctx, conn, name)
		if e != nil {
			t.Fatal(e)
		}
		access[name] = []Access{{Role: "stepca", Connect: true, Temporary: true}}
	}
	ca, e := os.ReadFile(os.Getenv("C8021X_PG_TEST_CA"))
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(ca)
	vars := map[string]any{"deployment_id": deployment, "host": p.Host, "port": p.Port, "administrator": "provisioning_admin", "admin_tool": tool, "ca_file": os.Getenv("C8021X_PG_TEST_CA"), "ca_pem_sha256": hex.EncodeToString(sum[:]), "reserved_ca_connections": 20, "expected_ca_acl": acl, "approved_ca_access": access, "passwords": map[string]string{"runtime": strings.Repeat("r", 32) + " +@/%", "native": strings.Repeat("n", 40), "migration": strings.Repeat("m", 40)}}
	data, e := json.Marshal(vars)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(temp, "terraform.tfvars.json"), data, 0600); e != nil {
		t.Fatal(e)
	}
	for _, args := range [][]string{{"init", "-backend=false", "-input=false"}, {"apply", "-auto-approve", "-input=false"}} {
		cmd := exec.CommandContext(ctx, "terraform", append([]string{"-chdir=" + temp}, args...)...)
		cmd.WaitDelay = 5 * time.Second
		cmd.Env = append(os.Environ(), "PGPASSWORD=disposable-admin", "TF_IN_AUTOMATION=1")
		out, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("disposable private runner %s: %v\n%s", args[0], e, out)
		}
	}
	for _, role := range roles {
		var safe bool
		if e = conn.QueryRow(ctx, `SELECT NOT(rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls) AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid) AND NOT has_database_privilege(r.oid,'stepca','CONNECT') AND NOT has_database_privilege(r.oid,'stepca_rsa','TEMP') FROM pg_roles r WHERE rolname=$1`, role).Scan(&safe); e != nil || !safe {
			t.Fatalf("unsafe %s %v", role, e)
		}
	}
	var owner string
	if e = conn.QueryRow(ctx, "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=$1", database).Scan(&owner); e != nil || owner != roles[2] {
		t.Fatalf("owner=%s error=%v", owner, e)
	}
	migrationDSN := "postgres://" + roles[2] + ":" + strings.Repeat("m", 40) + "@" + net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port))) + "/" + database
	store, e := postgres.NewMigration(ctx, migrationDSN, config.Database{Name: database, TLSMode: "verify-full", CAFile: os.Getenv("C8021X_PG_TEST_CA"), MinConnections: 0, MaxConnections: 8, ConnectTimeout: 5 * time.Second, QueryTimeout: 5 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	if e = store.Migrate(ctx, postgres.Roles{Runtime: roles[0], Native: roles[1]}); e != nil {
		t.Fatalf("actual non-superuser schema migration: %v", e)
	}

	output := exec.CommandContext(ctx, "terraform", "-chdir="+temp, "output", "-json", "application_dsns")
	encoded, e := output.Output()
	if e != nil {
		t.Fatal("sensitive DSN outputs unavailable")
	}
	var delivered map[string]string
	if json.Unmarshal(encoded, &delivered) != nil {
		t.Fatal("invalid DSN output")
	}
	for name, dsn := range delivered {
		candidate, e := pgx.ParseConfig(dsn)
		if e != nil {
			t.Fatal("encoded DSN rejected")
		}
		candidate.TLSConfig = p.TLSConfig
		candidate.Fallbacks = nil
		session, e := pgx.ConnectConfig(ctx, candidate)
		if e != nil {
			t.Fatalf("delivered %s credential failed", name)
		}
		var identity string
		if session.QueryRow(ctx, "SELECT current_user").Scan(&identity) != nil || identity != candidate.User {
			t.Fatal("wrong delivered identity")
		}
		_ = session.Close(ctx)
	}

	for _, name := range []string{"stepca", "stepca_rsa"} {
		actual, e := readCA(ctx, conn, name)
		if e != nil || !reflect.DeepEqual(actual, acl[name]) {
			t.Fatal("Terraform changed CA ACL or owner")
		}
	}
}
