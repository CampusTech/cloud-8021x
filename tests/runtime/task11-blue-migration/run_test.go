package main

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/config"
)

func TestDryRunNeverConstructsDatabasePool(t *testing.T) {
	// A constructor would immediately reject this missing CA and malformed DSN.
	// The independently validated entrypoint is tested separately; dry execution
	// must have no constructor/connection side effect even with unreachable data.
	if err := execute(context.Background(), prepared{Config: config.Defaults(), DSN: "deliberately invalid"}, true); err != nil {
		t.Fatal(err)
	}
}
func TestMigrationPoolNeverConsumesRuntimeAggregate(t *testing.T) {
	c := config.Defaults()
	got := migrationConfig(c.Database)
	if got.MaxConnections != 1 || got.MinConnections != 0 || got.QueryTimeout != c.Database.QueryTimeout || got.ConnectTimeout != c.Database.ConnectTimeout || c.Database.MaxConnections != 8 {
		t.Fatal("bounded migration allocation or original configuration changed")
	}
}
func TestUnvalidatedNonDryInputIsRefusedBeforeConstructor(t *testing.T) {
	err := execute(context.Background(), prepared{Config: config.Defaults(), DSN: "private-do-not-log"}, false)
	if err == nil || strings.Contains(err.Error(), "private-do-not-log") {
		t.Fatal("unvalidated input accepted or secret exposed")
	}
}
func TestCommandHasNoPathDatabaseOrRoleOverride(t *testing.T) {
	for _, flag := range []string{"--config", "--dsn", "--database", "--role", "--plan"} {
		c := command()
		c.SetArgs([]string{flag, "unapproved"})
		c.SetOut(io.Discard)
		c.SetErr(io.Discard)
		if c.Execute() == nil {
			t.Fatal("arbitrary override accepted")
		}
	}
}
