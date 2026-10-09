package main

import (
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/config"
)

func TestSyntheticSourceScopeCannotBecomeUsernameOrInternetAuthority(t *testing.T) {
	c := config.Defaults()
	c.Hostname = "task11-blue-primary"
	c.InstanceID = "radius-primary"
	c.Paths.InventoryFile = "/etc/freeradius/3.0/device-policy-cache.json"
	c.Policy.ClassSigningKey.File = "/run/radius-accounting-key"
	c.Listeners.Policy.Address = "127.0.0.1:9082"
	c.RadiusClients = []config.RadiusClient{{ID: "task11-nas", CIDRs: []string{"10.203.11.40/32"}, LocationID: "task11", Medium: "wifi", SignalingProfile: "unifi-numeric"}}
	c.Policy.Rules = []config.VLANRule{{GroupID: "fleet:1", LocationID: "task11", VLAN: 120}}
	if err := validateSourceScope(c); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*config.Config){func(c *config.Config) { c.Policy.IdentityMode = "legacy-serial" }, func(c *config.Config) { c.Listeners.Policy.Address = "0.0.0.0:9082" }, func(c *config.Config) { c.Paths.InventoryFile = "/tmp/inventory.json" }, func(c *config.Config) { c.RadiusClients = nil }, func(c *config.Config) { c.Policy.Rules = nil }, func(c *config.Config) { c.Hostname = "production-primary" }, func(c *config.Config) { c.Deployment.Mode = "parallel" }} {
		changed := c
		mutate(&changed)
		if validateSourceScope(changed) == nil {
			t.Fatal("source fixture scope widened")
		}
	}
	if err := validateSourceCache([]byte(`{"version":2,"updated_at":1800000000,"identities":{"arbitrary":null},"certificates":{},"hardware_serials":{}}`)); err == nil {
		t.Fatal("non-fixture snapshot admitted")
	}
	if err := validateSourceCache([]byte(strings.Repeat("x", 17<<20))); err == nil {
		t.Fatal("oversized source snapshot admitted")
	}
}
