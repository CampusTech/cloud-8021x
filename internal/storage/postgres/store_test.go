package postgres

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"
)

func TestLazyBoundedRedactedConnection(t *testing.T) {
	c := config.Defaults().Database
	c.CAFile = "/missing"
	c.MaxConnections = 0
	if _, err := New(context.Background(), "postgres://u:SENTINEL_SECRET@127.0.0.1:1/db", c); err == nil || strings.Contains(err.Error(), "SENTINEL_SECRET") {
		t.Fatal("bad config or secret leak", err)
	}
}
func integration(t *testing.T) (*Store, config.Database) {
	t.Helper()
	dsn := os.Getenv("C8021X_PG_TEST_DSN")
	if dsn == "" {
		t.Skip("run scripts/test_postgres.sh for real PostgreSQL16 integration")
	}
	c := config.Defaults().Database
	c.CAFile = os.Getenv("C8021X_PG_TEST_CA")
	c.ConnectTimeout = time.Second
	c.QueryTimeout = 3 * time.Second
	s, err := NewMigration(context.Background(), dsn, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if err = s.Migrate(context.Background(), Roles{Runtime: "app_runtime", Native: "app_native"}); err != nil {
		t.Fatal(err)
	}
	return s, c
}
func TestPostgresIntegration(t *testing.T) {
	s, _ := integration(t)
	if err := s.CheckDurability(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDSNPoolSettingsCannotOverrideLazyBounds(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
	if err != nil {
		t.Fatal(err)
	}
	c := config.Defaults().Database
	c.CAFile = filepath.Join(t.TempDir(), "ca.pem")
	c.MaxConnections = 2
	c.MinConnections = 1
	if err = os.WriteFile(c.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	// A small idle minimum safely reproduces the bug; never ask the buggy pool to
	// allocate huge idle resources. Large max/min values prove typed bounds win.
	dsn := "postgres://u:SENTINEL_SECRET@127.0.0.1:1/cloud8021x?pool_min_idle_conns=4&pool_min_conns=2147483647&pool_max_conns=2147483647"
	for _, mode := range []string{"runtime", "migration"} {
		t.Run(mode, func(t *testing.T) {
			constructor := New
			if mode == "migration" {
				constructor = NewMigration
			}
			s, err := constructor(context.Background(), dsn, c)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			actual := s.pool.Config()
			if actual.MinIdleConns != 0 || actual.MinConns != 0 || actual.MaxConns != 2 {
				t.Fatalf("DSN overrode lazy bounds: min_idle=%d min=%d max=%d", actual.MinIdleConns, actual.MinConns, actual.MaxConns)
			}
			if stat := s.pool.Stat(); stat.ConstructingConns() != 0 || stat.TotalConns() != 0 {
				t.Fatalf("lazy pool constructed connections: constructing=%d total=%d", stat.ConstructingConns(), stat.TotalConns())
			}
		})
	}
}
