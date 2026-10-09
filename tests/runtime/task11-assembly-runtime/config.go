package main

import (
	"errors"
	"reflect"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"
	seed "github.com/CampusTech/cloud-8021x/tests/runtime/task11-assembly-seed/contract"
)

func roleConfig(s seed.Input, role, transition string) (config.Config, error) {
	c := config.Defaults()
	if !reflect.DeepEqual(s.Credentials, seed.Credentials(s.Project)) || !reflect.DeepEqual(s.SourceCredentials, seed.SourceCredentials(s.Project)) {
		return c, errors.New("closed private credential bindings differ")
	}
	if role != "primary" && role != "secondary" {
		return c, errors.New("fixed role required")
	}
	refs := map[string]config.SecretRef{}
	for _, v := range s.Credentials {
		if _, ok := refs[v.ID]; ok {
			return c, errors.New("duplicate credential ID")
		}
		refs[v.ID] = config.SecretRef{File: v.File}
		c.Bootstrap.Secrets = append(c.Bootstrap.Secrets, config.BootstrapSecret{Resource: v.Resource, File: v.File, Owner: v.Owner})
	}
	c.SchemaVersion = 1
	c.InstanceID = "radius-" + role
	c.Hostname = "task11-green-" + role
	c.Environment = "task11-synthetic"
	c.StateTransition = transition
	c.Deployment = config.Deployment{Mode: "parallel", ID: "task11-green", Instance: c.Hostname, SourceID: "task11-blue", SourcePrimary: "task11-blue-primary", SourceSecondary: "task11-blue-secondary", CollectionEpoch: s.CollectionEpoch}
	c.Listeners.Policy.Address = "127.0.0.1:9080"
	c.Listeners.Policy.Token = refs["policy-token"]
	c.Listeners.HealthAddress = "127.0.0.1:9082"
	c.Listeners.MetricsAddress = "127.0.0.1:9083"
	c.Listeners.Webhook = config.TLSListener{Enabled: true, Address: "127.0.0.1:9444", CertFile: "/etc/cloud-8021x/webhook.crt", KeyFile: config.SecretRef{File: "/run/cloud-8021x/credentials/webhook.key"}, ClientCAFiles: []string{"/etc/cloud-8021x/client-cas.pem"}, ClientDNSNames: []string{s.ECDNS, s.RSADNS}}
	c.Listeners.Broker = config.BrokerListener{Enabled: true, Address: "0.0.0.0:9081", CertFile: c.Listeners.Webhook.CertFile, KeyFile: c.Listeners.Webhook.KeyFile, Username: "fleet", Token: refs["scep-broker-token"], SigningKey: refs["scep-challenge-key"], SCEPURL: "https://" + s.RSADNS + ":8444/scep/wifi-scep", Provisioner: "wifi-scep"}
	c.Inventory.Enabled = true
	c.Inventory.Fleet.BaseURL = "https://fleet.task11.test"
	c.Inventory.Fleet.ObserverToken = refs["fleet-observer-token"]
	c.Inventory.Fleet.MaintainerToken = refs["fleet-maintainer-token"]
	c.Inventory.Fleet.ManagedCertificates = true
	c.Inventory.Fleet.ClientCAFile = "/etc/cloud-8021x/client-cas.pem"
	c.Inventory.Fleet.CacheFile = "/var/cache/cloud-8021x/runtime/fleet.json"
	c.Inventory.Fleet.ChallengeSigningKey = refs["scep-challenge-key"]
	c.Inventory.Fleet.SCEPProvisioner = "wifi-scep"
	c.Policy.ClassSigningKey = refs["radius-accounting-class-key"]
	c.Policy.Rules = []config.VLANRule{{GroupID: "fleet:1", LocationID: "task11", VLAN: 120}}
	c.Network.Providers = []config.NetworkProvider{{ID: "task11-unifi", Kind: "unifi", BaseURL: "https://unifi.task11.test/v1", Credential: refs["unifi-token"], Scopes: []string{"task11-site"}, ConsoleID: "task11-console", Timeout: 5 * time.Second, CacheFile: "/var/cache/cloud-8021x/runtime/task11-unifi.json"}}
	c.Network.Locations = []config.Location{{ID: "task11", ProviderID: "task11-unifi", SiteID: "task11-site", VLANEnabled: true}}
	c.Network.Discovery.CandidateFile = "/var/lib/cloud-8021x/sources-candidate.json"
	c.RadiusClients = []config.RadiusClient{{ID: "task11-nas", LocationID: "task11", CIDRs: []string{"10.203.11.40/32"}, Secret: refs["radius-task11-secret"], Medium: "wifi", SignalingProfile: "unifi-numeric"}}
	c.Database.Name = seed.Database
	c.Database.RuntimeDSN = refs["postgres-runtime-dsn"]
	c.Database.MigrationDSN = refs["postgres-migration-dsn"]
	c.Database.NativeWriterDSN = refs["postgres-native-dsn"]
	c.Database.CAFile = "/etc/cloud-8021x/postgres-ca.pem"
	c.Database.TLSMode = "cloudsql-instance-ca"
	c.Database.CloudSQLInstance = s.SQLInstance
	c.Database.InstanceCAPEMSHA256 = s.PostgresCA.SHA256
	c.Telemetry.Enabled = true
	c.Telemetry.Endpoint = "http://127.0.0.1:4318"
	c.Telemetry.Logs = true
	c.Telemetry.Metrics = true
	c.Telemetry.Traces = true
	c.CA.URL = "https://" + s.ECDNS + ":8443"
	c.CA.RootFiles = []string{"/etc/cloud-8021x/client-cas.pem"}
	c.CA.IntermediateFiles = []string{"/etc/cloud-8021x/ec-intermediate.pem", "/etc/cloud-8021x/rsa-intermediate.pem"}
	c.CA.ConfigFile = "/etc/step-ca/config/ca.json"
	c.CA.ServerCertFile = "/etc/freeradius/3.0/certs/server-cert.pem"
	c.CA.ServerKeyFile = config.SecretRef{File: "/etc/freeradius/3.0/certs/server-key.pem"}
	c.CA.ReadinessFile = "/var/lib/step-ca/ready"
	b := &c.Bootstrap
	b.Project = s.Project
	b.ProjectNumber = s.ProjectNumber
	b.CAName = "Task11 synthetic"
	b.ECKMS = "cloudkms:projects/" + s.Project + "/locations/us-central1/keyRings/task11/cryptoKeys/ec/cryptoKeyVersions/1"
	b.RSAKMS = "cloudkms:projects/" + s.Project + "/locations/us-central1/keyRings/task11/cryptoKeys/rsa/cryptoKeyVersions/1"
	b.ECStagingSecret = "projects/" + s.Project + "/secrets/smallstep-ec-bootstrap-staging"
	b.RSAStagingSecret = "projects/" + s.Project + "/secrets/smallstep-rsa-bootstrap-staging"
	b.ECDNS = s.ECDNS
	b.RSADNS = s.RSADNS
	b.ServerDNS = s.ServerDNS
	b.ACMEProvisioner = "wifi-acme"
	b.SCEPProvisioner = "wifi-scep"
	b.ECDB = refs["stepca-dsn"]
	b.RSADB = refs["stepca-rsa-dsn"]
	b.RuntimeRole = seed.Database + "_runtime"
	b.NativeRole = seed.Database + "_native"
	b.LocalAddress = "10.203.11.21"
	b.PeerAddress = "10.203.11.22"
	b.PeerDNS = "task11-green-secondary"
	if role == "secondary" {
		b.LocalAddress, b.PeerAddress = b.PeerAddress, b.LocalAddress
		b.PeerDNS = "task11-green-primary"
	}
	b.HealthSecret = refs["peer-health"]
	b.DatadogSite = s.DatadogSite
	return c, nil
}

func sourceConfig(s seed.Input, role string) (config.Config, error) {
	c, err := roleConfig(s, role, "")
	if err != nil {
		return c, err
	}
	c.Deployment = config.Deployment{}
	c.Hostname = "task11-blue-" + role
	c.Database.Name = "cloud8021x_task11_blue"
	c.Bootstrap.RuntimeRole = c.Database.Name + "_runtime"
	c.Bootstrap.NativeRole = c.Database.Name + "_native"
	for i, v := range c.Bootstrap.Secrets {
		for _, blue := range s.SourceCredentials {
			if v.File == blue.File {
				c.Bootstrap.Secrets[i] = config.BootstrapSecret{Resource: blue.Resource, File: blue.File, Owner: blue.Owner}
			}
		}
	}
	c.Bootstrap.LocalAddress = "10.203.11.31"
	c.Bootstrap.PeerAddress = "10.203.11.32"
	c.Bootstrap.PeerDNS = "task11-blue-secondary"
	if role == "secondary" {
		c.Bootstrap.LocalAddress, c.Bootstrap.PeerAddress = c.Bootstrap.PeerAddress, c.Bootstrap.LocalAddress
		c.Bootstrap.PeerDNS = "task11-blue-primary"
	}
	c.Paths.InventoryFile = "/etc/freeradius/3.0/device-policy-cache.json"
	c.Paths.HandoffDir = "/run/radius-certificate-bindings"
	c.Policy.ClassSigningKey = config.SecretRef{File: "/run/radius-accounting-key"}
	c.Listeners.Policy.Address = "127.0.0.1:9082"
	c.Listeners.HealthAddress = "127.0.0.1:9084"
	return c, c.Validate()
}
