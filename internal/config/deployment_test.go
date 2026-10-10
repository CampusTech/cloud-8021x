package config

import (
	"strings"
	"testing"
	"time"
)

func parallelFixture() Config {
	c := Defaults()
	c.InstanceID = "radius-primary"
	c.StateTransition = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	c.Database.Name = "cloud8021x_green"
	c.Deployment = Deployment{Mode: "parallel", ID: "green", Instance: "green-primary", SourceID: "blue", SourcePrimary: "radius-primary", SourceSecondary: "radius-secondary", CollectionEpoch: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)}
	return c
}
func TestParallelDeploymentBinding(t *testing.T) {
	if err := parallelFixture().ValidateDeployment(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){
		"foreign physical instance": func(c *Config) { c.Deployment.Instance = "blue-primary" },
		"same deployment":           func(c *Config) { c.Deployment.SourceID = "green" },
		"same source nodes":         func(c *Config) { c.Deployment.SourceSecondary = c.Deployment.SourcePrimary },
		"missing epoch":             func(c *Config) { c.Deployment.CollectionEpoch = time.Time{} },
		"fractional epoch":          func(c *Config) { c.Deployment.CollectionEpoch = c.Deployment.CollectionEpoch.Add(time.Nanosecond) },
		"foreign role":              func(c *Config) { c.InstanceID = "green-primary" },
		"shared app database":       func(c *Config) { c.Database.Name = "cloud8021x" },
		"missing transition":        func(c *Config) { c.StateTransition = "" },
		"unsupported mode":          func(c *Config) { c.Deployment.Mode = "active" },
		"implicit mode":             func(c *Config) { c.Deployment.Mode = "" },
	} {
		t.Run(name, func(t *testing.T) {
			c := parallelFixture()
			mutate(&c)
			if c.ValidateDeployment() == nil {
				t.Fatal("unsafe deployment accepted")
			}
		})
	}
	if err := Defaults().ValidateDeployment(); err != nil {
		t.Fatal(err)
	}
}

func TestParallelHandoffRequiresFourDistinctPins(t *testing.T) {
	c := parallelFixture()
	if c.ValidateHandoffPins() == nil {
		t.Fatal("missing reverse identities accepted")
	}
	c.Deployment.SourcePrimaryKey = strings.Repeat("1", 64)
	c.Deployment.SourceSecondaryKey = strings.Repeat("2", 64)
	c.Deployment.DestinationPrimaryKey = strings.Repeat("3", 64)
	c.Deployment.DestinationSecondaryKey = strings.Repeat("4", 64)
	if err := c.ValidateHandoffPins(); err != nil {
		t.Fatal(err)
	}
	c.Deployment.DestinationSecondaryKey = c.Deployment.SourcePrimaryKey
	if c.ValidateHandoffPins() == nil {
		t.Fatal("one key impersonated multiple physical hosts")
	}
}
