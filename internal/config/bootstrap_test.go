package config

import "testing"

func TestBootstrapRequiresFixedPathsAndSecretBindings(t *testing.T) {
	c := Defaults()
	if c.ValidateBootstrap() == nil {
		t.Fatal("missing deployment accepted")
	}
	c.Bootstrap.Project = "fixture-project"
	c.Bootstrap.Secrets = []BootstrapSecret{{Resource: "projects/fixture-project/secrets/token", File: "/etc/sudoers", Owner: "runtime"}}
	if c.ValidateBootstrap() == nil {
		t.Fatal("arbitrary root destination accepted")
	}
}
