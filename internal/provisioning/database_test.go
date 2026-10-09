package provisioning

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
	"github.com/jackc/pgx/v5"
)

func TestCAProvisioningTLSAndACL(t *testing.T) {
	dsn := os.Getenv("C8021X_PG_TEST_DSN")
	if dsn == "" {
		t.Skip("owned PostgreSQL TLS fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, e := pgx.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	p.Database = "postgres"
	p.TLSConfig, e = postgres.VerifiedTLSConfig(config.Database{TLSMode: "verify-full", CAFile: os.Getenv("C8021X_PG_TEST_CA")}, p.Host)
	if e != nil {
		t.Fatal(e)
	}
	p.Fallbacks = nil
	conn, e := pgx.ConnectConfig(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = conn.Close(ctx) }()
	for _, q := range []string{"CREATE ROLE stepca LOGIN PASSWORD 'disposable-ca'", "CREATE DATABASE stepca", "CREATE DATABASE stepca_rsa"} {
		if _, e = conn.Exec(ctx, q); e != nil {
			t.Fatal(e)
		}
	}
	defer func() {
		for _, q := range []string{"DROP DATABASE stepca WITH (FORCE)", "DROP DATABASE stepca_rsa WITH (FORCE)", "DROP ROLE stepca"} {
			_, _ = conn.Exec(context.Background(), q)
		}
	}()
	caBytes, e := os.ReadFile(os.Getenv("C8021X_PG_TEST_CA"))
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(caBytes)
	c := Config{Host: p.Host, Port: p.Port, Administrator: p.User, CAFile: os.Getenv("C8021X_PG_TEST_CA"), TLSMode: "verify-full", CAPin: hex.EncodeToString(sum[:]), RuntimeLimit: 16, NativeLimit: 4, MigrationLimit: 2, ReservedConnections: 20, ExpectedCA: map[string]DatabaseACL{}, ApprovedCAAccess: map[string][]Access{}}
	t.Setenv("PGPASSWORD", p.Password)
	for _, name := range []string{"stepca", "stepca_rsa"} {
		c.ExpectedCA[name], e = readCA(ctx, conn, name)
		if e != nil {
			t.Fatal(e)
		}
		c.ApprovedCAAccess[name] = []Access{{Role: "stepca", Connect: true, Temporary: true}}
	}
	if _, e = Check(ctx, c); e == nil {
		t.Fatal("unhardened PUBLIC access passed")
	}
	if e = Harden(ctx, c, false); e != nil {
		t.Fatal(e)
	}
	if _, e = Check(ctx, c); e == nil {
		t.Fatal("dry-run mutated ACL")
	}
	if e = Harden(ctx, c, true); e != nil {
		t.Fatal(e)
	}
	if _, e = Check(ctx, c); e != nil {
		t.Fatal(e)
	}
	if e = Harden(ctx, c, true); e != nil {
		t.Fatalf("exact completed hardening not idempotent: %v", e)
	}
	var caConnect, caTemp, runtimeConnect, nativeConnect bool
	if e = conn.QueryRow(ctx, `SELECT has_database_privilege('stepca','stepca','CONNECT'),has_database_privilege('stepca','stepca_rsa','TEMP'),has_database_privilege('app_runtime','stepca','CONNECT'),has_database_privilege('app_native','stepca_rsa','CONNECT')`).Scan(&caConnect, &caTemp, &runtimeConnect, &nativeConnect); e != nil {
		t.Fatal(e)
	}
	if !caConnect || !caTemp || runtimeConnect || nativeConnect {
		t.Fatalf("ca=%v/%v app=%v/%v", caConnect, caTemp, runtimeConnect, nativeConnect)
	}
	ca := p.Copy()
	ca.User = "stepca"
	ca.Password = "disposable-ca"
	ca.Database = "stepca"
	sentinel, e := pgx.ConnectConfig(ctx, ca)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = sentinel.Exec(ctx, "CREATE TEMP TABLE ca_connection_sentinel (value int); INSERT INTO ca_connection_sentinel VALUES (8021)"); e != nil {
		t.Fatal(e)
	}
	var value int
	if e = sentinel.QueryRow(ctx, "SELECT value FROM ca_connection_sentinel").Scan(&value); e != nil || value != 8021 {
		t.Fatal("CA session unavailable")
	}
	_ = sentinel.Close(ctx)
	broken := c
	broken.CAFile = os.Getenv("C8021X_PG_TEST_WRONG_CA")
	if _, e = Check(ctx, broken); e == nil {
		t.Fatal("wrong CA accepted")
	}

	wrongBytes, e := os.ReadFile(broken.CAFile)
	if e != nil {
		t.Fatal(e)
	}
	wrongSum := sha256.Sum256(wrongBytes)
	broken.CAPin = hex.EncodeToString(wrongSum[:])
	if _, e = Check(ctx, broken); e == nil {
		t.Fatal("wrong trusted CA chain accepted despite a matching file pin")
	}
	broken = c
	broken.ReservedConnections = 100000
	if _, e = Check(ctx, broken); e == nil {
		t.Fatal("capacity deficit accepted")
	}
	if _, e = conn.Exec(ctx, "GRANT CONNECT ON DATABASE stepca TO app_runtime"); e != nil {
		t.Fatal(e)
	}
	if _, e = Check(ctx, c); e == nil {
		t.Fatal("unknown ACL drift accepted")
	}
	if e = Harden(ctx, c, true); e == nil {
		t.Fatal("hardening erased unknown ACL drift")
	}
	if strings.Contains(e.Error(), p.Password) {
		t.Fatal("credential exposed")
	}
}
