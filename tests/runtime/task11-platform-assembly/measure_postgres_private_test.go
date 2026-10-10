package main

import (
	"context"
	"testing"
)

func TestMeasureBaseExcludesPrerequisiteGeneratedPostgresClusterConfig(t *testing.T) {
	root, fd := openBaseFixture(t)
	baseFixtureFile(t, root, "/usr/bin/public", []byte("public package"), 0755)
	baseFixtureFile(t, root, "/etc/postgresql/17/main/postgresql.conf", []byte("local cluster configuration"), 0600)
	baseFixtureFile(t, root, "/etc/postgresql/17/main/pg_hba.conf", []byte("local authentication configuration"), 0600)
	m, err := measureLowerAt(context.Background(), fd, 200000, 1664*MiB)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range m.Entries {
		if entry.Path == "/etc/postgresql" || entry.Path == "/etc/postgresql/17/main/postgresql.conf" || entry.Path == "/etc/postgresql/17/main/pg_hba.conf" {
			t.Fatalf("prerequisite-generated private cluster configuration projected: %s", entry.Path)
		}
	}
}
