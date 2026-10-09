package config

import (
	"errors"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Bootstrap is non-secret root configuration. Secret destinations are restricted
// to the fixed credential directories, with ownership selected from typed roles.
// Artifact acquisition is deliberately separate; bootstrap consumes the fixed
// root-owned manifest at /var/cache/cloud-8021x/artifacts/manifest.json.
type Bootstrap struct {
	ProjectNumber    string            `yaml:"project_number"`
	ECStagingSecret  string            `yaml:"ec_staging_secret"`
	RSAStagingSecret string            `yaml:"rsa_staging_secret"`
	Project          string            `yaml:"project"`
	CAName           string            `yaml:"ca_name"`
	ECKMS            string            `yaml:"ec_kms"`
	RSAKMS           string            `yaml:"rsa_kms"`
	ECDNS            string            `yaml:"ec_dns"`
	RSADNS           string            `yaml:"rsa_dns"`
	ServerDNS        string            `yaml:"server_dns"`
	ACMEProvisioner  string            `yaml:"acme_provisioner"`
	SCEPProvisioner  string            `yaml:"scep_provisioner"`
	ECDB             SecretRef         `yaml:"ec_database_dsn"`
	RSADB            SecretRef         `yaml:"rsa_database_dsn"`
	RuntimeRole      string            `yaml:"runtime_role"`
	NativeRole       string            `yaml:"native_role"`
	LocalAddress     string            `yaml:"local_address"`
	PeerAddress      string            `yaml:"peer_address"`
	PeerDNS          string            `yaml:"peer_dns"`
	HealthSecret     SecretRef         `yaml:"health_secret"`
	Secrets          []BootstrapSecret `yaml:"secrets"`
	DatadogSite      string            `yaml:"datadog_site"`
}
type BootstrapSecret struct {
	Resource string `yaml:"resource"`
	File     string `yaml:"file"`
	Owner    string `yaml:"owner"`
}

func (c Config) ValidateBootstrap() error {
	b := c.Bootstrap
	if !regexp.MustCompile(`^[1-9][0-9]{5,19}$`).MatchString(b.ProjectNumber) {
		return errors.New("bootstrap requires pinned numeric project")
	}
	staging := regexp.MustCompile(`^projects/` + regexp.QuoteMeta(b.Project) + `/secrets/[A-Za-z0-9_-]{1,255}$`)
	if !staging.MatchString(b.ECStagingSecret) || !staging.MatchString(b.RSAStagingSecret) || b.ECStagingSecret == b.RSAStagingSecret {
		return errors.New("distinct root-only EC/RSA staging secrets required")
	}
	if !regexp.MustCompile(`^[a-z][a-z0-9-]{4,62}$`).MatchString(b.Project) || b.CAName == "" || len(b.CAName) > 128 || strings.ContainsAny(b.CAName, "\r\n\x00") {
		return errors.New("bootstrap requires project and CA name")
	}
	kms := regexp.MustCompile(`^cloudkms:projects/` + regexp.QuoteMeta(b.Project) + `/locations/[a-z0-9-]+/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+/cryptoKeyVersions/[0-9]+$`)
	if !kms.MatchString(b.ECKMS) || !kms.MatchString(b.RSAKMS) || b.ECKMS == b.RSAKMS {
		return errors.New("bootstrap requires distinct pinned EC/RSA KMS key versions")
	}
	name := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$`)
	for _, n := range []string{b.ECDNS, b.RSADNS, b.ServerDNS, b.PeerDNS, b.ACMEProvisioner, b.SCEPProvisioner} {
		if !name.MatchString(n) {
			return errors.New("invalid bootstrap DNS or provisioner")
		}
	}
	for _, ip := range []string{b.LocalAddress, b.PeerAddress} {
		a, e := netip.ParseAddr(ip)
		if e != nil || !a.Is4() || !a.IsPrivate() {
			return errors.New("bootstrap health requires explicit private IPv4 peers")
		}
	}
	if b.LocalAddress == b.PeerAddress {
		return errors.New("bootstrap peers must differ")
	}
	role := regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
	if !role.MatchString(b.RuntimeRole) || !role.MatchString(b.NativeRole) || b.RuntimeRole == b.NativeRole || b.RuntimeRole == "stepca" || b.NativeRole == "stepca" {
		return errors.New("invalid dedicated application database roles")
	}
	if c.Parallel() && (b.RuntimeRole != c.Database.Name+"_runtime" || b.NativeRole != c.Database.Name+"_native") {
		return errors.New("parallel roles must belong to the deployment database namespace")
	}
	// Fixed installed boundaries: root never derives commands or service paths
	// from a daemon-controlled leaf/candidate or an overridden CLI configuration.
	if c.RuntimeUser != "cloud8021x" || c.Backends.RadiusBinary != "/usr/sbin/freeradius" || c.Backends.RadiusConfigDir != "/etc/freeradius/3.0" || c.Backends.RadiusService != "freeradius" || c.Backends.StepCAService != "step-ca" || c.Backends.RadiusVerifyLeafDir != "/run/radius-verified-leaves" || c.Paths.HandoffDir != "/run/radius-certificate-bindings" {
		return errors.New("bootstrap requires fixed installed backend and account paths")
	}
	resources, files := map[string]bool{}, map[string]string{}
	for _, s := range b.Secrets {
		if !regexp.MustCompile(`^projects/`+regexp.QuoteMeta(b.Project)+`/secrets/[A-Za-z0-9_-]{1,255}$`).MatchString(s.Resource) || resources[s.Resource] || files[s.File] != "" {
			return errors.New("invalid or duplicate bootstrap secret mapping")
		}
		parent := filepath.Dir(s.File)
		switch s.Owner {
		case "runtime":
			if parent != "/run/cloud-8021x/credentials" {
				return errors.New("runtime credential requires fixed private directory")
			}
		case "root":
			if parent != "/run/cloud-8021x-root" {
				return errors.New("root credential requires fixed private directory")
			}
		case "collector":
			if parent != "/run/cloud-8021x-collector" {
				return errors.New("collector credential requires fixed private directory")
			}
		default:
			return errors.New("invalid credential owner")
		}
		if s.File == "/run/cloud-8021x-root/credential-set.json" || s.File == "/run/cloud-8021x/credentials/webhook.key" || s.File == "/run/cloud-8021x-collector/datadog.env" {
			return errors.New("generated credential path cannot be a secret mapping")
		}
		if !regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`).MatchString(filepath.Base(s.File)) {
			return errors.New("invalid credential basename")
		}
		files[s.File] = s.Owner
		resources[s.Resource] = true
	}
	for _, r := range []SecretRef{c.Database.RuntimeDSN, c.Listeners.Policy.Token, c.Policy.ClassSigningKey, b.HealthSecret} {
		if files[r.File] != "runtime" {
			return errors.New("required runtime secret mapping missing")
		}
	}
	for _, r := range []SecretRef{c.Database.MigrationDSN, c.Database.NativeWriterDSN, b.ECDB, b.RSADB} {
		if files[r.File] != "root" {
			return errors.New("required protected root secret mapping missing")
		}
	}
	for _, client := range c.RadiusClients {
		if files[client.Secret.File] != "root" {
			return errors.New("RADIUS shared secret requires root mapping")
		}
	}
	if b.DatadogSite != "datadoghq.com" && b.DatadogSite != "us3.datadoghq.com" && b.DatadogSite != "us5.datadoghq.com" && b.DatadogSite != "datadoghq.eu" && b.DatadogSite != "ap1.datadoghq.com" && b.DatadogSite != "ap2.datadoghq.com" {
		return errors.New("unsupported bootstrap Datadog site")
	}

	if b.HealthSecret.File == c.Listeners.Policy.Token.File || b.HealthSecret.File == c.Policy.ClassSigningKey.File {
		return errors.New("separate peer health credential required")
	}
	for _, provider := range c.Network.Providers {
		if files[provider.Credential.File] != "runtime" {
			return errors.New("network runtime secret mapping missing")
		}
	}
	if c.Inventory.Enabled {
		refs := []SecretRef{c.Inventory.Fleet.ObserverToken}
		if c.Inventory.Fleet.ManagedCertificates {
			refs = append(refs, c.Inventory.Fleet.MaintainerToken, c.Inventory.Fleet.ChallengeSigningKey)
		}
		for _, ref := range refs {
			if files[ref.File] != "runtime" {
				return errors.New("Fleet runtime secret mapping missing")
			}
		}
	}
	if c.Listeners.Broker.Enabled {
		for _, ref := range []SecretRef{c.Listeners.Broker.Token, c.Listeners.Broker.SigningKey} {
			if files[ref.File] != "runtime" {
				return errors.New("broker runtime secret mapping missing")
			}
		}
	}
	if c.Listeners.Broker.Enabled && c.Listeners.Broker.KeyFile.File != "/run/cloud-8021x/credentials/webhook.key" && files[c.Listeners.Broker.KeyFile.File] != "runtime" {
		return errors.New("broker TLS key requires inherited protected credential")
	}
	if c.Telemetry.Credential.File != "" && files[c.Telemetry.Credential.File] != "runtime" {
		return errors.New("telemetry runtime secret mapping missing")
	}
	if len(c.CA.RootFiles) != 1 || c.CA.RootFiles[0] != "/etc/cloud-8021x/client-cas.pem" || c.CA.ServerCertFile != "/etc/freeradius/3.0/certs/server-cert.pem" || c.CA.ServerKeyFile.File != "/etc/freeradius/3.0/certs/server-key.pem" {
		return errors.New("fixed installed RADIUS certificates and client bundle required")
	}
	if c.Inventory.Enabled && c.Inventory.Fleet.ManagedCertificates && c.Inventory.Fleet.ClientCAFile != c.CA.RootFiles[0] {
		return errors.New("managed collection must use the same complete client trust bundle")
	}
	if c.Policy.AttestedACME.Enabled && c.Policy.AttestedACME.IssuerFile != "/etc/cloud-8021x/ec-intermediate.pem" {
		return errors.New("attested ACME requires installed public EC issuer")
	}
	if files["/run/cloud-8021x-collector/datadog-api-key"] != "collector" {
		return errors.New("fixed collector-only API credential mapping required")
	}
	if !c.Listeners.Webhook.Enabled || c.Listeners.Webhook.CertFile != "/etc/cloud-8021x/webhook.crt" || c.Listeners.Webhook.KeyFile.File != "/run/cloud-8021x/credentials/webhook.key" {
		return errors.New("fixed legacy-compatible webhook TLS paths required")
	}
	if len(c.Listeners.Webhook.ClientDNSNames) != 2 || !slices.Contains(c.Listeners.Webhook.ClientDNSNames, b.ECDNS) || !slices.Contains(c.Listeners.Webhook.ClientDNSNames, b.RSADNS) || len(c.Listeners.Webhook.ClientCAFiles) != 1 || c.Listeners.Webhook.ClientCAFiles[0] != "/etc/cloud-8021x/client-cas.pem" {
		return errors.New("webhook mTLS requires both configured CA DNS names and complete preserved trust")
	}
	for _, s := range b.Secrets {
		if s.Resource == b.ECStagingSecret || s.Resource == b.RSAStagingSecret {
			return errors.New("CA recovery staging secrets cannot be runtime credentials")
		}
	}
	return nil
}
