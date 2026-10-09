package host

import (
	"context"
	"encoding/json"
	"os"
	"runtime"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
)

func TestInstalledFreshDatabaseTLSBeforeTrustPublication(t *testing.T) {
	if os.Getenv("C8021X_CA_INPUT_FIXTURE") != "task10" {
		t.Skip("owned TLS PostgreSQL/root fixture required")
	}
	ctx := context.Background()
	if err := protectedDirectory(ArtifactDirectory, 0, 0, 0700); err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile("/fixture/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	m := fixtureManifest()
	m.Architecture = runtime.GOARCH
	for i := range m.Artifacts {
		m.Artifacts[i].Architecture = runtime.GOARCH
	}
	m.PostgresCASHA256 = digestBytes(ca)
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(ArtifactManifest, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(IncomingPostgresCAFile, ca, 0600); err != nil {
		t.Fatal(err)
	}
	db := config.Defaults().Database
	db.CAFile, db.InstanceCAPEMSHA256 = PostgresCAFile, m.PostgresCASHA256
	if _, err := os.Stat(PostgresCAFile); !os.IsNotExist(err) {
		t.Fatal("fixture is not fresh", err)
	}
	const dsn = "postgres://postgres:task10-synthetic-admin@localhost:5432/cloud8021x"
	if _, err := postgres.NewMigration(ctx, dsn, db); err == nil {
		t.Fatal("fresh installed-path connection unexpectedly succeeded")
	}
	preflight, data, err := IncomingDatabase(db)
	if err != nil {
		t.Fatal(err)
	}
	store, err := postgres.NewMigration(ctx, dsn, preflight)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	// Migrate performs real authenticated TLS I/O, rather than merely constructing a lazy pool.
	if err = store.Migrate(ctx, postgres.Roles{Runtime: "app_runtime", Native: "app_native"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(PostgresCAFile); !os.IsNotExist(err) {
		t.Fatal("preflight published live trust", err)
	}
	candidate := File{Path: PostgresCAFile, Data: data, Mode: 0644}
	if err = PrepareFileDirectories([]File{candidate}); err != nil {
		t.Fatal(err)
	}
	previous, err := Snapshot(candidate)
	if err != nil || previous.Exists {
		t.Fatal("fresh snapshot", err)
	}
	if err = Write(candidate); err != nil {
		t.Fatal(err)
	}
	installed, err := postgres.NewMigration(ctx, dsn, db)
	if err != nil {
		t.Fatal(err)
	}
	if err = installed.Migrate(ctx, postgres.Roles{Runtime: "app_runtime", Native: "app_native"}); err != nil {
		t.Fatal(err)
	}
	installed.Close()
	if err = os.WriteFile(PostgresCAFile, append(data, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = postgres.NewMigration(ctx, dsn, db); err == nil {
		t.Fatal("altered installed trust bypassed exact pin")
	}
	if err = Restore(previous); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(PostgresCAFile); !os.IsNotExist(err) {
		t.Fatal("fresh rollback left a trust artifact", err)
	}
}
