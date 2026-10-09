package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/jackc/pgx/v5"
)

func pinFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func TestPostgresTLSModesAndBounds(t *testing.T) {
	admin, c := integration(t)
	ctx := context.Background()
	dsn := roleDSN(t, "app_runtime", "disposable-runtime")
	t.Run("verified-hostname", func(t *testing.T) {
		s, err := New(ctx, dsn, c)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if err = s.CheckDurability(ctx); err != nil {
			t.Fatal(err)
		}
	})
	u, _ := url.Parse(dsn)
	u.Host = "127.0.0.1:" + u.Port()
	ipDSN := u.String()
	t.Run("wrong-hostname", func(t *testing.T) {
		s, err := New(ctx, ipDSN, c)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if err = s.CheckDurability(ctx); err == nil {
			t.Fatal("hostname not verified")
		}
	})
	instance := c
	instance.TLSMode = "cloudsql-instance-ca"
	instance.CloudSQLInstance = "campus-test:us-central1:isolated-test"
	instance.InstanceCAPEMSHA256 = pinFile(t, c.CAFile)
	t.Run("pinned-instance-chain-without-hostname", func(t *testing.T) {
		s, err := New(ctx, ipDSN, instance)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if err = s.CheckDurability(ctx); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("wrong-pin", func(t *testing.T) {
		bad := instance
		bad.InstanceCAPEMSHA256 = strings.Repeat("0", 64)
		if s, err := New(ctx, ipDSN, bad); err == nil {
			s.Close()
			t.Fatal("wrong pin accepted")
		}
	})
	t.Run("extra-ca", func(t *testing.T) {
		bad := instance
		b, _ := os.ReadFile(c.CAFile)
		bad.CAFile = filepath.Join(t.TempDir(), "bundle.pem")
		if err := os.WriteFile(bad.CAFile, append(b, b...), 0600); err != nil {
			t.Fatal(err)
		}
		bad.InstanceCAPEMSHA256 = pinFile(t, bad.CAFile)
		if s, err := New(ctx, ipDSN, bad); err == nil {
			s.Close()
			t.Fatal("CA bundle accepted")
		}
	})
	t.Run("wrong-chain", func(t *testing.T) {
		bad := instance
		bad.CAFile = os.Getenv("C8021X_PG_TEST_WRONG_CA")
		bad.InstanceCAPEMSHA256 = pinFile(t, bad.CAFile)
		s, err := New(ctx, ipDSN, bad)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if err = s.CheckDurability(ctx); err == nil {
			t.Fatal("wrong instance chain accepted")
		}
	})
	t.Run("unsafe-modes", func(t *testing.T) {
		for _, mode := range []string{"require", "disable", "prefer", "allow"} {
			bad := c
			bad.TLSMode = mode
			if s, err := New(ctx, dsn, bad); err == nil {
				s.Close()
				t.Fatal("unsafe mode", mode)
			}
		}
	})
	t.Run("dsn-cannot-disable-tls", func(t *testing.T) {
		s, err := New(ctx, ipDSN+"?sslmode=disable", c)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if err = s.CheckDurability(ctx); err == nil {
			t.Fatal("DSN disabled verification")
		}
	})
	t.Run("lazy-outage-and-secret-redaction", func(t *testing.T) {
		u, _ := url.Parse(dsn)
		u.Host = "127.0.0.1:1"
		u.User = url.UserPassword("app_runtime", "SENTINEL_SECRET")
		start := time.Now()
		s, err := New(ctx, u.String(), c)
		if err != nil {
			t.Fatal("lazy constructor connected", err)
		}
		defer s.Close()
		if time.Since(start) > time.Second {
			t.Fatal("startup waited for DB")
		}
		err = s.CheckDurability(ctx)
		if err == nil || strings.Contains(err.Error(), "SENTINEL_SECRET") || strings.Contains(err.Error(), u.String()) {
			t.Fatal("operational error leaked", err)
		}
	})
	t.Run("no-tls-no-fallback", func(t *testing.T) {
		setSSL := func(value string) {
			t.Helper()
			if _, err := admin.pool.Exec(ctx, "ALTER SYSTEM SET ssl = '"+value+"'"); err != nil {
				t.Fatal(err)
			}
			if _, err := admin.pool.Exec(ctx, "SELECT pg_reload_conf()"); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 100; i++ {
				var ssl string
				if err := admin.pool.QueryRow(ctx, "SHOW ssl").Scan(&ssl); err != nil {
					t.Fatal(err)
				}
				if ssl == value {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Fatal("ssl reload timeout")
		}
		defer setSSL("on")
		setSSL("off")
		s, err := New(ctx, dsn, c)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if err = s.CheckDurability(ctx); err == nil {
			t.Fatal("plaintext fallback accepted")
		}
	})
}
func TestPostgresRoleIsolationAndHijack(t *testing.T) {
	admin, c := integration(t)
	reset(t, admin)
	ctx := context.Background()
	runtime := runtimeStore(t, admin, c)
	native := roleStore(t, c, "app_native", "disposable-native")
	for _, q := range []string{"SELECT * FROM ledger.intake", "UPDATE ledger.intake SET host='x'", "DELETE FROM ledger.intake", "SELECT * FROM ledger.sessions", "CREATE TABLE ledger.evil(i int)", "CREATE TEMP TABLE sessions(i int)", "SELECT ledger.queue_session()"} {
		if _, err := native.pool.Exec(ctx, q); err == nil {
			t.Fatalf("native privilege accepted: %s", q)
		}
	}
	for _, q := range []string{"UPDATE ledger.legacy_usage_floor SET credit_start='0'", "DELETE FROM ledger.legacy_usage_floor", "INSERT INTO ledger.legacy_usage_floor(singleton,transition,credit_start) VALUES(true,repeat('a',64),'0')", "CREATE TABLE ledger.evil(i int)", "CREATE TEMP TABLE sessions(i int)", "CREATE ROLE evil", "ALTER TABLE ledger.intake ADD evil text", "UPDATE ledger.observations SET reason='rewritten'", "DELETE FROM ledger.intervals"} {
		if _, err := runtime.pool.Exec(ctx, q); err == nil {
			t.Fatalf("runtime privilege accepted: %s", q)
		}
	}
	conn, err := native.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err = conn.Exec(ctx, "SET search_path=pg_temp,public,ledger"); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(ctx, `INSERT INTO ledger.intake(received_at,source_ip,client_id,location_id,host,replay_id,nas_ip,nas_count,station,station_count,session_id,session_count,status,status_count,input_octets,input_octets_count) VALUES(now(),'192.0.2.1','client','site','host','r','192.0.2.2',1,'aa:bb:cc:dd:ee:ff',1,'evil''; DROP SCHEMA ledger CASCADE; --',1,'???',2,'oops',1)`); err != nil {
		t.Fatal("raw malformed intake rejected by trigger", err)
	}
	if count(t, admin, "sessions") != 1 || count(t, admin, "intake") != 1 {
		t.Fatal("search path or injection corrupted schema")
	}
	for _, role := range []string{"app_runtime", "app_native"} {
		dsn := roleDSN(t, role, "disposable-"+strings.TrimPrefix(role, "app_"))
		u, _ := url.Parse(dsn)
		u.Path = "/ca_sentinel"
		pc, err := pgx.ParseConfig(u.String())
		if err != nil {
			t.Fatal(err)
		}
		pc.TLSConfig, err = tlsConfig(c, pc.Host)
		if err != nil {
			t.Fatal(err)
		}
		pc.Fallbacks = nil
		db, err := pgx.ConnectConfig(ctx, pc)
		if err == nil {
			_ = db.Close(ctx)
			t.Fatal("application role can connect to CA database", role)
		}
	}
	for _, q := range []string{"GRANT pg_read_all_data TO app_runtime", "ALTER ROLE app_runtime CREATEDB"} {
		if _, err = admin.pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
		bad := runtimeStore(t, admin, c)
		if err = bad.CheckDurability(ctx); err == nil {
			t.Fatal("elevated runtime role accepted", q)
		}
		bad.Close()
		if _, err = admin.pool.Exec(ctx, "REVOKE pg_read_all_data FROM app_runtime; ALTER ROLE app_runtime NOCREATEDB"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = admin.pool.Exec(ctx, "UPDATE ledger.sessions SET upload=18446744073709551616"); err == nil {
		t.Fatal("uint64 upper bound missing")
	}
	if _, err = admin.pool.Exec(ctx, "UPDATE ledger.sessions SET download=-1"); err == nil {
		t.Fatal("uint64 lower bound missing")
	}
	// Independent privileged connection proves the pre-existing CA sentinel unchanged.
	u, _ := url.Parse(os.Getenv("C8021X_PG_TEST_DSN"))
	u.Path = "/ca_sentinel"
	ca, err := NewMigration(ctx, u.String(), c)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Close()
	var sentinel string
	if err = ca.pool.QueryRow(ctx, "SELECT secret FROM ca_keys").Scan(&sentinel); err != nil || sentinel != "untouched-test-sentinel" {
		t.Fatal("CA state changed", err)
	}
}
func TestInvalidConnectionConfigurationDoesNotLeak(t *testing.T) {
	c := config.Defaults().Database
	c.CAFile = "/missing"
	for _, dsn := range []string{"postgres://u:SENTINEL_SECRET@localhost/db?pool_max_conns=oops", "postgres://u:SENTINEL_SECRET@localhost/db?sslmode=unexpected"} {
		if s, err := New(context.Background(), dsn, c); err == nil {
			s.Close()
			t.Fatal("bad DSN accepted")
		} else if strings.Contains(err.Error(), "SENTINEL_SECRET") {
			t.Fatal("secret leaked", err)
		}
	}
}

func TestPostgresMigrationRejectsElevatedWriter(t *testing.T) {
	admin, _ := integration(t)
	ctx := context.Background()
	if _, err := admin.pool.Exec(ctx, "ALTER ROLE app_native CREATEROLE"); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.pool.Exec(ctx, "ALTER ROLE app_native NOCREATEROLE") }()
	if err := admin.Migrate(ctx, Roles{Runtime: "app_runtime", Native: "app_native"}); err == nil {
		t.Fatal("migration accepted privileged native writer")
	}
}

func TestPostgresMigrationRejectsWrongDatabase(t *testing.T) {
	_, c := integration(t)
	ctx := context.Background()
	u, _ := url.Parse(os.Getenv("C8021X_PG_TEST_DSN"))
	u.Path = "/ca_sentinel"
	wrong, err := NewMigration(ctx, u.String(), c)
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	if err = wrong.Migrate(ctx, Roles{Runtime: "app_runtime", Native: "app_native"}); err == nil {
		t.Fatal("migration created application schema in CA database")
	}
	var exists bool
	if err = wrong.pool.QueryRow(ctx, "SELECT to_regnamespace('ledger') IS NOT NULL").Scan(&exists); err != nil || exists {
		t.Fatal("wrong database changed", exists, err)
	}
}
