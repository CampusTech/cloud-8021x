package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"
	seed "github.com/CampusTech/cloud-8021x/tests/runtime/task11-assembly-seed/contract"
	"gopkg.in/yaml.v3"
)

func configInput() seed.Input {
	s := seed.Input{Schema: 1, Project: "task11-acceptance", ProjectNumber: "111222333444", SQLInstance: "task11-acceptance:us-central1:task11-postgres", ECDNS: "ec.task11.test", RSADNS: "rsa.task11.test", ServerDNS: "radius.task11.test", CollectionEpoch: time.Unix(1800000000, 0).UTC(), DatadogSite: "us5.datadoghq.com", PostgresCA: seed.FilePin{Path: "postgres/postgres-ca.pem", SHA256: strings.Repeat("a", 64)}}
	s.Credentials = seed.Credentials(s.Project)
	s.SourceCredentials = seed.SourceCredentials(s.Project)
	return s
}
func TestRoleCandidatesPassActualShippingValidators(t *testing.T) {
	for _, role := range []string{"primary", "secondary"} {
		c, err := roleConfig(configInput(), role, strings.Repeat("b", 64))
		if err != nil {
			t.Fatal(err)
		}
		if err = c.Validate(); err != nil {
			t.Fatalf("complete shipping %s config: %v", role, err)
		}
		if err = c.ValidateBootstrap(); err != nil {
			t.Fatalf("complete shipping %s bootstrap: %v", role, err)
		}
		raw, err := yaml.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		round, err := config.Decode(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		if round.Database.MaxConnections != 8 || round.Deployment.Instance != "task11-green-"+role || round.InstanceID != "radius-"+role || round.Policy.Rules[0].VLAN != 120 || round.Network.Discovery.Enabled {
			t.Fatal("authority/capacity pairing changed")
		}
		if c.ValidateHandoffPins() == nil {
			t.Fatal("candidate fabricated enrolled receipt pins")
		}
	}
}

func TestSourceCandidatesKeepBlueDatabaseAndRetainedAuthority(t *testing.T) {
	for _, role := range []string{"primary", "secondary"} {
		c, err := sourceConfig(configInput(), role)
		if err != nil {
			t.Fatal(err)
		}
		if err = c.Validate(); err != nil {
			t.Fatal(err)
		}
		if c.Database.Name != "cloud8021x_task11_blue" || c.Deployment != (config.Deployment{}) || c.Hostname != "task11-blue-"+role || c.Paths.InventoryFile != "/etc/freeradius/3.0/device-policy-cache.json" || c.Policy.ClassSigningKey.File != "/run/radius-accounting-key" || c.Listeners.Policy.Address != "127.0.0.1:9082" {
			t.Fatal("source authority or ledger differs")
		}
		for _, ref := range c.Bootstrap.Secrets {
			if strings.Contains(ref.Resource, "postgres-") && !strings.Contains(ref.Resource, "postgres-blue-") {
				t.Fatal("source refers to green credentials")
			}
		}
		if c.Bootstrap.RuntimeRole != "cloud8021x_task11_blue_runtime" || c.Bootstrap.NativeRole != "cloud8021x_task11_blue_native" {
			t.Fatal("blue roles differ")
		}
	}
}
func TestRejectChangedCredentialBinding(t *testing.T) {
	s := configInput()
	s.Credentials[0].File = "/run/elsewhere"
	if _, err := roleConfig(s, "primary", strings.Repeat("b", 64)); err == nil {
		t.Fatal("changed private binding accepted")
	}
}
func TestShippingValidatorRequiresNeutralProvider(t *testing.T) {
	c, err := roleConfig(configInput(), "primary", strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	c.Network.Providers = nil
	if c.Validate() == nil {
		t.Fatal("missing required location provider accepted")
	}
}
func TestUnknownOriginalSourcePathCannotBecomeCandidate(t *testing.T) {
	s := configInput()
	files := map[string][]byte{"source/etc/sudoers.d/evil": []byte("bad")}
	if err := validateOriginalFiles(files); err == nil {
		t.Fatal("arbitrary original source path accepted")
	}
	if err := validateOriginalFiles(map[string][]byte{}); err == nil {
		t.Fatal("missing original state accepted")
	}
	_ = s
}
