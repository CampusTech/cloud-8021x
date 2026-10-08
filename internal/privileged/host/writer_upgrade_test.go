package host

import (
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/config"
)

func TestWriterUpgradeRejectsAuthorityChanges(t *testing.T) {
	old := config.Config{InstanceID: "radius-primary", StateTransition: strings.Repeat("a", 64)}
	old.Bootstrap.Project = "project"
	old.Bootstrap.ProjectNumber = "123456"
	old.Bootstrap.LocalAddress = "10.0.0.1"
	old.Bootstrap.PeerAddress = "10.0.0.2"
	next := old
	next.Debug = true
	if e := ValidateWriterUpgrade(old, next); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*config.Config){func(c *config.Config) { c.StateTransition = strings.Repeat("b", 64) }, func(c *config.Config) { c.InstanceID = "radius-secondary" }, func(c *config.Config) { c.Bootstrap.Project = "foreign" }, func(c *config.Config) { c.Bootstrap.PeerAddress = "10.0.0.3" }, func(c *config.Config) { c.Database.CloudSQLInstance = "foreign" }} {
		next = old
		change(&next)
		if e := ValidateWriterUpgrade(old, next); e == nil {
			t.Fatal("uncoordinated authority change accepted")
		}
	}
}
