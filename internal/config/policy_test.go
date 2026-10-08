package config

import (
	"os"
	"strings"
	"testing"
)

func TestPrivateHandoffActorAndFixedLeafDirectory(t *testing.T) {
	data, err := os.ReadFile("../../examples/cloud-8021x.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Decode(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RuntimeUser != "cloud8021x" || cfg.Backends.RadiusVerifyLeafDir != "/run/freeradius/verified-leaves" {
		t.Fatal("missing separate actor defaults")
	}
	for _, user := range []string{"root", "freerad", "", "a/b"} {
		copy := cfg
		copy.RuntimeUser = user
		if copy.Validate() == nil {
			t.Fatal("unsafe runtime user", user)
		}
	}
	copy := cfg
	copy.Backends.RadiusVerifyLeafDir = copy.Paths.HandoffDir
	if copy.Validate() == nil {
		t.Fatal("leaf input and app-only private handoff directory cannot be shared")
	}
}
func TestOptOutRulesAndMappedIPv6AreRejected(t *testing.T) {
	data, err := os.ReadFile("../../examples/cloud-8021x.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Decode(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Network.Locations) == 0 {
		t.Fatal("fixture locations")
	}
	cfg.Network.Locations[0].VLANEnabled = false
	if cfg.Validate() == nil {
		t.Fatal("optout with explicit mapping")
	}
	cfg, err = Decode(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	cfg.RadiusClients[0].CIDRs = []string{"::ffff:192.0.2.0/120"}
	if cfg.Validate() == nil {
		t.Fatal("mapped IP can select foreign source family")
	}
}
