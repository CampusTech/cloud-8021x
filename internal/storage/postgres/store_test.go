package postgres

import (
	"context"
	"os"
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
