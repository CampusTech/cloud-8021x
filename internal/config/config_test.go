package config

import (
	"strings"
	"testing"
	"time"
)

const validYAML = `schema_version: 1
database:
  runtime_dsn: {file: /run/cloud-8021x/runtime-dsn}
  migration_dsn: {file: /run/cloud-8021x/migration-dsn}
  native_writer_dsn: {file: /run/cloud-8021x/native-dsn}
  ca_file: /etc/cloud-8021x/postgres-ca.pem
`

func TestStrictVersionedConfig(t *testing.T) {
	cfg, err := Decode(strings.NewReader(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SchemaVersion != 1 || cfg.Database.MaxConnections < 1 || cfg.Policy.InventoryMaxAge != time.Hour {
		t.Fatalf("missing typed defaults: %+v", cfg)
	}
	for _, bad := range []string{
		strings.Replace(validYAML, "schema_version: 1", "schema_version: 2", 1),
		strings.Replace(validYAML, "schema_version: 1", "", 1),
		validYAML + "jamf: {}\n", validYAML + "okta: {}\n", validYAML + "unknown: true\n",
		strings.Replace(validYAML, "database:", "database:\n  password: leaked-value", 1),
		strings.Replace(validYAML, "database:", "database:\n  max_connections: 0", 1),
		strings.Replace(validYAML, "database:", "database:\n  tls_mode: disable", 1),
		strings.Replace(validYAML, "file: /run/cloud-8021x/runtime-dsn", "value: leaked-value", 1),
		strings.Replace(validYAML, "file: /run/cloud-8021x/runtime-dsn", "file: relative-secret", 1),
		strings.Replace(validYAML, "file: /run/cloud-8021x/runtime-dsn", "file: /run/../tmp/secret", 1),
		validYAML + "---\nschema_version: 1\n", validYAML + "schema_version: 1\n",
		validYAML + "listeners:\n  policy:\n    address: 0.0.0.0:9000\n    token: {file: /run/token}\n",
		validYAML + "policy:\n  identity_mode: username\n",
		validYAML + "telemetry:\n  trace_sample_ratio: 1.1\n",
		validYAML + "schedules:\n  inventory: -1s\n",
		validYAML + "network:\n  providers:\n    - id: retired\n      kind: jamf\n",
	} {
		_, err := Decode(strings.NewReader(bad))
		if err == nil {
			t.Fatalf("accepted invalid config %q", bad)
		}
		if strings.Contains(err.Error(), "leaked-value") {
			t.Fatal("error exposed secret input")
		}
	}
}

func TestConfigRejectsScopeAndVLANConflicts(t *testing.T) {
	base := validYAML + `network:
  providers:
    - id: controller
      kind: meraki
      base_url: https://api.meraki.com
      credential: {file: /run/meraki-token}
      scopes: [organization]
  locations:
    - id: nyc
      provider_id: controller
      site_id: network-1
      vlan_enabled: true
`
	if _, err := Decode(strings.NewReader(base)); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{
		"policy:\n  rules:\n    - {group_id: 'fleet:staff', location_id: nyc, vlan: 4095}\n",
		"policy:\n  rules:\n    - {group_id: 'fleet:staff', location_id: missing, vlan: 20}\n",
		"radius_clients:\n  - {id: ap, location_id: nyc, medium: wired, cidrs: ['10.0.0.0/24'], secret: {file: /run/radius-token}}\n",
		"radius_clients:\n  - {id: ap, location_id: nyc, medium: wifi, cidrs: ['0.0.0.0/0'], secret: {file: /run/radius-token}}\n",
	} {
		if _, err := Decode(strings.NewReader(base + suffix)); err == nil {
			t.Fatalf("accepted %s", suffix)
		}
	}
	dup := strings.Replace(base, "      vlan_enabled: true", "      vlan_enabled: true\n    - {id: other, provider_id: controller, site_id: network-1}", 1)
	if _, err := Decode(strings.NewReader(dup)); err == nil {
		t.Fatal("accepted ambiguous provider/site mapping")
	}
}

func TestCompatibilityFreshnessDefaults(t *testing.T) {
	c := Defaults()
	if c.Policy.InventoryMaxAge != time.Hour || c.Policy.HandoffMaxAge != 120*time.Second || c.Policy.ClassMaxAge != 30*24*time.Hour || c.Network.Discovery.MaxAge != 15*time.Minute || c.Schedules.Sources != time.Minute || c.Paths.HandoffDir != "/run/radius-certificate-bindings" {
		t.Fatalf("changed deployed defaults: %+v", c)
	}
}

func TestRejectsNaNSamplingAndOversizedConfig(t *testing.T) {
	if _, err := Decode(strings.NewReader(validYAML + "telemetry:\n  trace_sample_ratio: .nan\n")); err == nil {
		t.Fatal("NaN sampling accepted")
	}
	if _, err := Decode(strings.NewReader(strings.Repeat(" ", MaxConfigBytes+1))); err == nil {
		t.Fatal("oversized config accepted")
	}
}

func TestSeparateDatabaseCredentialsAndCollectionScope(t *testing.T) {
	shared := strings.Replace(validYAML, "/run/cloud-8021x/migration-dsn", "/run/cloud-8021x/runtime-dsn", 1)
	if _, err := Decode(strings.NewReader(shared)); err == nil {
		t.Fatal("shared privileged/runtime database credential accepted")
	}
	for _, suffix := range []string{"", "inventory:\n  fleet:\n    scep_profile_uuids: null\n", "inventory:\n  fleet:\n    scep_profile_uuids: []\n"} {
		c, err := Decode(strings.NewReader(validYAML + suffix))
		if err != nil {
			t.Fatal(err)
		}
		if (c.Inventory.Fleet.SCEPProfileUUIDs == nil) != (suffix == "" || strings.Contains(suffix, "null")) {
			t.Fatal("lost null versus empty polling scope")
		}
	}
}

func TestExplicitSiteOptOutSurvivesDecode(t *testing.T) {
	c, err := Decode(strings.NewReader(validYAML + `network:
  providers:
    - {id: meraki, kind: meraki, base_url: 'https://api.meraki.com', credential: {file: /run/token}, scopes: [org]}
  locations:
    - {id: sacramento, provider_id: meraki, site_id: net, vlan_enabled: false}
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Network.Locations[0].VLANEnabled {
		t.Fatal("explicit opt-out enabled")
	}
}

func TestPinnedCloudSQLInstanceCAMode(t *testing.T) {
	extra := "  tls_mode: cloudsql-instance-ca\n  cloud_sql_instance: campus-dev:us-central1:shared-postgres\n  instance_ca_pem_sha256: '" + strings.Repeat("a", 64) + "'\n"
	good := strings.Replace(validYAML, "database:\n", "database:\n"+extra, 1)
	if _, err := Decode(strings.NewReader(good)); err != nil {
		t.Fatalf("explicit pinned per-instance CA mode rejected: %v", err)
	}
	for _, bad := range []string{
		strings.Replace(good, "  instance_ca_pem_sha256: '"+strings.Repeat("a", 64)+"'\n", "", 1),
		strings.Replace(good, strings.Repeat("a", 64), strings.Repeat("g", 64), 1),
		strings.Replace(good, strings.Repeat("a", 64), "abcd", 1),
		strings.Replace(good, "campus-dev:us-central1:shared-postgres", "", 1),
		strings.Replace(good, "campus-dev:us-central1:shared-postgres", "host.example", 1),
		strings.Replace(good, "campus-dev:us-central1:shared-postgres", "campus-dev:us-central1:postgres; command", 1),
		strings.Replace(good, "cloudsql-instance-ca", "require", 1),
		strings.Replace(good, "ca_file: /etc/cloud-8021x/postgres-ca.pem", "ca_file: ''", 1),
	} {
		if _, err := Decode(strings.NewReader(bad)); err == nil {
			t.Fatalf("insecure Cloud SQL mode accepted: %q", bad)
		}
	}
}
