// Package config defines the versioned, non-secret application configuration.
package config

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var cloudSQLInstancePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]:[a-z]+-[a-z]+[0-9]:[a-z][a-z0-9-]{0,97}$`)

const SchemaVersion = 1
const MaxConfigBytes = 1 << 20

// SecretRef refers to a protected local file, never an inline secret or remote URL.
// Validation does not open it; privileged and runtime credentials may have different owners.
type SecretRef struct {
	File string `yaml:"file"`
}

type Config struct {
	StateTransition string         `yaml:"state_transition"`
	Bootstrap       Bootstrap      `yaml:"bootstrap"`
	RuntimeUser     string         `yaml:"runtime_user"`
	SchemaVersion   int            `yaml:"schema_version"`
	Debug           bool           `yaml:"debug"`
	InstanceID      string         `yaml:"instance_id"`
	Environment     string         `yaml:"environment"`
	Hostname        string         `yaml:"hostname"`
	Listeners       Listeners      `yaml:"listeners"`
	Inventory       Inventory      `yaml:"inventory"`
	Policy          Policy         `yaml:"policy"`
	Network         Network        `yaml:"network"`
	RadiusClients   []RadiusClient `yaml:"radius_clients"`
	Database        Database       `yaml:"database"`
	Telemetry       Telemetry      `yaml:"telemetry"`
	CA              CA             `yaml:"ca"`
	Backends        Backends       `yaml:"backends"`
	Paths           Paths          `yaml:"paths"`
	Schedules       Schedules      `yaml:"schedules"`
}

type Listener struct {
	Address        string        `yaml:"address"`
	Token          SecretRef     `yaml:"token"`
	MaxConcurrency int           `yaml:"max_concurrency"`
	MaxBodyBytes   int           `yaml:"max_body_bytes"`
	Timeout        time.Duration `yaml:"timeout"`
}
type TLSListener struct {
	Enabled        bool      `yaml:"enabled"`
	Address        string    `yaml:"address"`
	CertFile       string    `yaml:"cert_file"`
	KeyFile        SecretRef `yaml:"key_file"`
	ClientCAFiles  []string  `yaml:"client_ca_files"`
	ClientDNSNames []string  `yaml:"client_dns_names"`
}
type BrokerListener struct {
	Enabled     bool      `yaml:"enabled"`
	Address     string    `yaml:"address"`
	CertFile    string    `yaml:"cert_file"`
	KeyFile     SecretRef `yaml:"key_file"`
	Username    string    `yaml:"username"`
	Token       SecretRef `yaml:"token"`
	SigningKey  SecretRef `yaml:"signing_key"`
	SCEPURL     string    `yaml:"scep_url"`
	Provisioner string    `yaml:"provisioner"`
}
type Listeners struct {
	Policy         Listener       `yaml:"policy"`
	Webhook        TLSListener    `yaml:"webhook"`
	Broker         BrokerListener `yaml:"broker"`
	HealthAddress  string         `yaml:"health_address"`
	MetricsAddress string         `yaml:"metrics_address"`
}
type Inventory struct {
	Enabled  bool   `yaml:"enabled"`
	Provider string `yaml:"provider"`
	Fleet    Fleet  `yaml:"fleet"`
}
type Fleet struct {
	ClientCAFile     string   `yaml:"client_ca_file"`
	ACMEProfileUUIDs []string `yaml:"acme_profile_uuids"`
	// Nil means all eligible non-exempt hosts; an explicit [] means queue none.
	SCEPProfileUUIDs    []string      `yaml:"scep_profile_uuids"`
	PollInterval        time.Duration `yaml:"poll_interval"`
	MaxPendingAge       time.Duration `yaml:"max_pending_age"`
	BaseURL             string        `yaml:"base_url"`
	ObserverToken       SecretRef     `yaml:"observer_token"`
	MaintainerToken     SecretRef     `yaml:"maintainer_token"`
	ManagedCertificates bool          `yaml:"managed_certificates"`
	TeamIDs             []string      `yaml:"team_ids"`
	HostIDs             []string      `yaml:"host_ids"`
	AllowLabel          string        `yaml:"allow_label"`
	Timeout             time.Duration `yaml:"timeout"`
	CacheFile           string        `yaml:"cache_file"`
	ChallengeSigningKey SecretRef     `yaml:"challenge_signing_key"`
	SCEPProvisioner     string        `yaml:"scep_provisioner"`
}

// AttestedACME enables only the pinned, verified device-attest-01 recognition path.
type AttestedACME struct {
	Enabled     bool   `yaml:"enabled"`
	IssuerFile  string `yaml:"issuer_file"`
	Provisioner string `yaml:"provisioner"`
}

type Policy struct {
	AttestedACME      AttestedACME  `yaml:"attested_acme"`
	IdentityMode      string        `yaml:"identity_mode"`
	InventoryMaxAge   time.Duration `yaml:"inventory_max_age"`
	CertificateMaxAge time.Duration `yaml:"certificate_max_age"`
	HandoffMaxAge     time.Duration `yaml:"handoff_max_age"`
	ClassMaxAge       time.Duration `yaml:"class_max_age"`
	ClassSigningKey   SecretRef     `yaml:"class_signing_key"`
	FallbackVLAN      int           `yaml:"fallback_vlan"`
	Rules             []VLANRule    `yaml:"rules"`
}
type VLANRule struct {
	GroupID    string `yaml:"group_id"`
	LocationID string `yaml:"location_id"`
	VLAN       int    `yaml:"vlan"`
}
type Network struct {
	MetadataMaxAge time.Duration     `yaml:"metadata_max_age"`
	Providers      []NetworkProvider `yaml:"providers"`
	Locations      []Location        `yaml:"locations"`
	Discovery      Discovery         `yaml:"discovery"`
}
type NetworkProvider struct {
	ConsoleID      string        `yaml:"console_id"`
	OrganizationID string        `yaml:"organization_id"`
	ID             string        `yaml:"id"`
	Kind           string        `yaml:"kind"`
	BaseURL        string        `yaml:"base_url"`
	Credential     SecretRef     `yaml:"credential"`
	Scopes         []string      `yaml:"scopes"`
	Timeout        time.Duration `yaml:"timeout"`
	CacheFile      string        `yaml:"cache_file"`
}
type Location struct {
	ID          string `yaml:"id"`
	ProviderID  string `yaml:"provider_id"`
	SiteID      string `yaml:"site_id"`
	VLANEnabled bool   `yaml:"vlan_enabled"`
}
type SourceBinding struct {
	ProviderID string `yaml:"provider_id"`
	ClientID   string `yaml:"client_id"`
}
type SourceFirewall struct {
	Project string `yaml:"project"`
	Node    string `yaml:"node"`
	Network string `yaml:"network"`
}
type Discovery struct {
	Bindings      []SourceBinding `yaml:"bindings"`
	Firewall      SourceFirewall  `yaml:"firewall"`
	Enabled       bool            `yaml:"enabled"`
	MaxAge        time.Duration   `yaml:"max_age"`
	CandidateFile string          `yaml:"candidate_file"`
}
type RadiusClient struct {
	ID               string    `yaml:"id"`
	LocationID       string    `yaml:"location_id"`
	CIDRs            []string  `yaml:"cidrs"`
	Secret           SecretRef `yaml:"secret"`
	Medium           string    `yaml:"medium"`
	SignalingProfile string    `yaml:"signaling_profile"`
}
type Database struct {
	// cloudsql-instance-ca requires this explicit instance and exact trusted CA PEM pin.
	CloudSQLInstance    string        `yaml:"cloud_sql_instance"`
	InstanceCAPEMSHA256 string        `yaml:"instance_ca_pem_sha256"`
	RuntimeDSN          SecretRef     `yaml:"runtime_dsn"`
	MigrationDSN        SecretRef     `yaml:"migration_dsn"`
	NativeWriterDSN     SecretRef     `yaml:"native_writer_dsn"`
	CAFile              string        `yaml:"ca_file"`
	TLSMode             string        `yaml:"tls_mode"`
	MinConnections      int           `yaml:"min_connections"`
	MaxConnections      int           `yaml:"max_connections"`
	ConnectTimeout      time.Duration `yaml:"connect_timeout"`
	QueryTimeout        time.Duration `yaml:"query_timeout"`
}
type Telemetry struct {
	// BusinessEndpoint is a separate synchronous HTTP/protobuf durable receiver.
	BusinessEndpoint string        `yaml:"business_endpoint"`
	Enabled          bool          `yaml:"enabled"`
	Endpoint         string        `yaml:"endpoint"`
	Transport        string        `yaml:"transport"`
	Logs             bool          `yaml:"logs"`
	Metrics          bool          `yaml:"metrics"`
	Traces           bool          `yaml:"traces"`
	CAFile           string        `yaml:"ca_file"`
	Credential       SecretRef     `yaml:"credential"`
	Timeout          time.Duration `yaml:"timeout"`
	ShutdownTimeout  time.Duration `yaml:"shutdown_timeout"`
	QueueSize        int           `yaml:"queue_size"`
	TraceSampleRatio float64       `yaml:"trace_sample_ratio"`
}
type CA struct {
	Provider          string    `yaml:"provider"`
	URL               string    `yaml:"url"`
	RootFiles         []string  `yaml:"root_files"`
	IntermediateFiles []string  `yaml:"intermediate_files"`
	ConfigFile        string    `yaml:"config_file"`
	DatabaseDSN       SecretRef `yaml:"database_dsn"`
	KMSKey            string    `yaml:"kms_key"`
	SCEPKey           SecretRef `yaml:"scep_key"`
	ServerCertFile    string    `yaml:"server_cert_file"`
	ServerKeyFile     SecretRef `yaml:"server_key_file"`
	ReadinessFile     string    `yaml:"readiness_file"`
}
type Backends struct {
	RadiusVerifyLeafDir string `yaml:"radius_verify_leaf_dir"`
	RadiusBinary        string `yaml:"radius_binary"`
	RadiusConfigDir     string `yaml:"radius_config_dir"`
	RadiusService       string `yaml:"radius_service"`
	StepBinary          string `yaml:"step_binary"`
	StepCAService       string `yaml:"step_ca_service"`
	CollectorConfigFile string `yaml:"collector_config_file"`
}
type Paths struct {
	StateDir           string `yaml:"state_dir"`
	CacheDir           string `yaml:"cache_dir"`
	HandoffDir         string `yaml:"handoff_dir"`
	InventoryFile      string `yaml:"inventory_file"`
	MetadataFile       string `yaml:"metadata_file"`
	AuthLogDir         string `yaml:"auth_log_dir"`
	AccountingSpoolDir string `yaml:"accounting_spool_dir"`
	DowngradeGuardFile string `yaml:"downgrade_guard_file"`
	LegacyStateDir     string `yaml:"legacy_state_dir"`
}
type Schedules struct {
	Inventory         time.Duration `yaml:"inventory"`
	Certificates      time.Duration `yaml:"certificates"`
	Sites             time.Duration `yaml:"sites"`
	Sources           time.Duration `yaml:"sources"`
	Metrics           time.Duration `yaml:"metrics"`
	AccountingWorkers int           `yaml:"accounting_workers"`
	ExportWorkers     int           `yaml:"export_workers"`
}

func Defaults() Config {
	return Config{
		RuntimeUser: "cloud8021x",
		Listeners:   Listeners{Policy: Listener{MaxConcurrency: 64, MaxBodyBytes: 16 << 10, Timeout: 2 * time.Second}},
		Inventory:   Inventory{Provider: "fleet", Fleet: Fleet{Timeout: 5 * time.Second, PollInterval: time.Hour, MaxPendingAge: 24 * time.Hour}},
		Policy:      Policy{IdentityMode: "fingerprint", InventoryMaxAge: time.Hour, CertificateMaxAge: 24 * time.Hour, HandoffMaxAge: 120 * time.Second, ClassMaxAge: 30 * 24 * time.Hour},
		Network:     Network{MetadataMaxAge: time.Hour, Discovery: Discovery{MaxAge: 15 * time.Minute}},
		Database:    Database{TLSMode: "verify-full", MinConnections: 0, MaxConnections: 8, ConnectTimeout: 5 * time.Second, QueryTimeout: 5 * time.Second},
		Telemetry:   Telemetry{BusinessEndpoint: "http://127.0.0.1:4319", Transport: "http", Timeout: 5 * time.Second, ShutdownTimeout: 10 * time.Second, QueueSize: 1024, TraceSampleRatio: 0.1},
		CA:          CA{Provider: "step-ca"},
		Backends:    Backends{RadiusVerifyLeafDir: "/run/radius-verified-leaves", RadiusBinary: "/usr/sbin/freeradius", RadiusConfigDir: "/etc/freeradius/3.0", RadiusService: "freeradius", StepBinary: "/usr/bin/step", StepCAService: "step-ca", CollectorConfigFile: "/etc/cloud-8021x/ddot.yaml"},
		Paths:       Paths{StateDir: "/var/lib/cloud-8021x", CacheDir: "/var/cache/cloud-8021x", HandoffDir: "/run/radius-certificate-bindings", InventoryFile: "/var/lib/cloud-8021x/inventory.json", MetadataFile: "/var/lib/cloud-8021x/metadata.json", AuthLogDir: "/var/log/freeradius/auth", AccountingSpoolDir: "/var/log/freeradius/radacct", DowngradeGuardFile: "/var/lib/cloud-8021x/fingerprint-enforced", LegacyStateDir: "/var/lib/fleet-radius"},
		Schedules:   Schedules{Inventory: 5 * time.Minute, Certificates: time.Hour, Sites: 5 * time.Minute, Sources: time.Minute, Metrics: time.Minute, AccountingWorkers: 2, ExportWorkers: 1},
	}
}

// Load strictly decodes and validates a configuration before returning it.
func Load(path string) (Config, error) {
	cfg, err := LoadForOverrides(path)
	if err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// LoadForOverrides strictly decodes and applies defaults, but defers semantic
// validation. Callers MUST apply supported overrides and Validate before use.
func LoadForOverrides(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open configuration: %w", err)
	}
	defer func() { _ = f.Close() }()
	return decodeForOverrides(f)
}

// Decode strictly decodes and validates a configuration.
func Decode(r io.Reader) (Config, error) {
	cfg, err := decodeForOverrides(r)
	if err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func decodeForOverrides(r io.Reader) (Config, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxConfigBytes+1))
	if err != nil {
		return Config{}, errors.New("read configuration failed")
	}
	if len(data) > MaxConfigBytes {
		return Config{}, errors.New("configuration exceeds 1 MiB")
	}
	cfg := Defaults()
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		// Decoder error text can quote inline values. Never echo untrusted config contents.
		return Config{}, errors.New("invalid YAML configuration: check syntax, types, duplicate and unknown fields; Okta/Jamf settings must be removed")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("configuration must contain exactly one YAML document")
	}
	return cfg, nil
}

func (r SecretRef) Validate(field string, required bool) error {
	if r.File == "" && !required {
		return nil
	}
	if !cleanPath(r.File) {
		return fmt.Errorf("%s requires an absolute, clean secret file reference", field)
	}
	return nil
}
func cleanPath(p string) bool {
	return p != "" && filepath.IsAbs(p) && filepath.Clean(p) == p && p != "/" && !strings.ContainsAny(p, "\x00\r\n")
}
func duration(d time.Duration, max time.Duration) bool { return d > 0 && d <= max }
func httpsURL(s string) bool {
	u, e := url.Parse(s)
	return e == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}
func listenAddress(s string, loopback bool) bool {
	_, err := parseListenerBinding(s, loopback)
	return err == nil
}

func parseListenerBinding(s string, loopback bool) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return netip.AddrPort{}, errors.New("listener requires numeric IP and port")
	}
	for _, digit := range port {
		if digit < '0' || digit > '9' {
			return netip.AddrPort{}, errors.New("listener port must be decimal")
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return netip.AddrPort{}, errors.New("listener port out of bounds")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return netip.AddrPort{}, errors.New("listener requires unscoped numeric IP")
	}
	ip = ip.Unmap()
	if loopback && !ip.IsLoopback() {
		return netip.AddrPort{}, errors.New("listener requires loopback IP")
	}
	return netip.AddrPortFrom(ip, uint16(n)), nil
}

func listenerBindingsOverlap(a, b netip.AddrPort) bool {
	// Wildcard listeners are conservatively treated as dual-stack because the
	// operating system and tcp listener's IPV6_V6ONLY defaults can differ.
	return a.Port() == b.Port() && (a.Addr() == b.Addr() || a.Addr().IsUnspecified() || b.Addr().IsUnspecified())
}

func (c Config) Validate() error {
	if c.StateTransition != "" && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(c.StateTransition) {
		return errors.New("state_transition must be a protected shared 64-hex identity")
	}
	if !regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`).MatchString(c.RuntimeUser) || c.RuntimeUser == "root" || c.RuntimeUser == "freerad" || c.RuntimeUser == "freeradius" {
		return errors.New("runtime_user must be a separate unprivileged daemon account")
	}
	if !cleanPath(c.Backends.RadiusVerifyLeafDir) || c.Backends.RadiusVerifyLeafDir == c.Paths.HandoffDir {
		return errors.New("verified leaf input requires a fixed directory distinct from private daemon handoffs")
	}
	if c.SchemaVersion != SchemaVersion {
		return errors.New("unsupported or missing schema_version; expected 1")
	}
	refs := []struct {
		name     string
		ref      SecretRef
		required bool
	}{
		{"database.runtime_dsn", c.Database.RuntimeDSN, true}, {"database.migration_dsn", c.Database.MigrationDSN, true}, {"database.native_writer_dsn", c.Database.NativeWriterDSN, true},
		{"listeners.policy.token", c.Listeners.Policy.Token, c.Listeners.Policy.Address != ""},
		{"inventory.fleet.observer_token", c.Inventory.Fleet.ObserverToken, c.Inventory.Enabled},
		{"inventory.fleet.maintainer_token", c.Inventory.Fleet.MaintainerToken, c.Inventory.Enabled && c.Inventory.Fleet.ManagedCertificates},
		{"inventory.fleet.challenge_signing_key", c.Inventory.Fleet.ChallengeSigningKey, false},
		{"policy.class_signing_key", c.Policy.ClassSigningKey, c.Listeners.Policy.Address != ""},
		{"listeners.webhook.key_file", c.Listeners.Webhook.KeyFile, c.Listeners.Webhook.Enabled},
		{"listeners.broker.key_file", c.Listeners.Broker.KeyFile, c.Listeners.Broker.Enabled},
		{"listeners.broker.token", c.Listeners.Broker.Token, c.Listeners.Broker.Enabled},
		{"listeners.broker.signing_key", c.Listeners.Broker.SigningKey, c.Listeners.Broker.Enabled},
		{"telemetry.credential", c.Telemetry.Credential, false}, {"ca.database_dsn", c.CA.DatabaseDSN, false}, {"ca.scep_key", c.CA.SCEPKey, false}, {"ca.server_key_file", c.CA.ServerKeyFile, false},
	}
	for _, r := range refs {
		if err := r.ref.Validate(r.name, r.required); err != nil {
			return err
		}
	}
	if c.Database.RuntimeDSN.File == c.Database.MigrationDSN.File || c.Database.RuntimeDSN.File == c.Database.NativeWriterDSN.File || c.Database.MigrationDSN.File == c.Database.NativeWriterDSN.File {
		return errors.New("runtime, migration and native-writer database credentials require separate files")
	}

	if !cleanPath(c.Database.CAFile) {
		return errors.New("database requires an absolute trusted ca_file")
	}
	switch c.Database.TLSMode {
	case "verify-full":
	case "cloudsql-instance-ca":
		pin, err := hex.DecodeString(c.Database.InstanceCAPEMSHA256)
		if err != nil || len(pin) != 32 || !cloudSQLInstancePattern.MatchString(c.Database.CloudSQLInstance) {
			return errors.New("cloudsql-instance-ca TLS requires a 64-hex instance_ca_pem_sha256 pin and canonical project:region:instance cloud_sql_instance")
		}
	default:
		return errors.New("database requires verify-full TLS or explicit pinned cloudsql-instance-ca TLS")
	}
	if c.Database.MinConnections < 0 || c.Database.MaxConnections < 1 || c.Database.MaxConnections > 64 || c.Database.MinConnections > c.Database.MaxConnections || !duration(c.Database.ConnectTimeout, time.Minute) || !duration(c.Database.QueryTimeout, time.Minute) {
		return errors.New("database pool or timeout out of bounds")
	}
	p := c.Listeners.Policy
	if p.Address != "" && !listenAddress(p.Address, true) {
		return errors.New("policy listener must use a numeric loopback address and valid port")
	}
	if p.MaxConcurrency < 1 || p.MaxConcurrency > 1024 || p.MaxBodyBytes < 1 || p.MaxBodyBytes > 1<<20 || !duration(p.Timeout, 10*time.Second) {
		return errors.New("policy listener bounds invalid")
	}
	var bindings []netip.AddrPort
	addListener := func(address string, loopback bool) error {
		binding, err := parseListenerBinding(address, loopback)
		if err != nil {
			return err
		}
		for _, existing := range bindings {
			if listenerBindingsOverlap(binding, existing) {
				return errors.New("listeners use overlapping bind addresses")
			}
		}
		bindings = append(bindings, binding)
		return nil
	}
	for _, address := range []string{p.Address, c.Listeners.HealthAddress, c.Listeners.MetricsAddress} {
		if address != "" {
			if err := addListener(address, true); err != nil {
				return fmt.Errorf("local listener: %w", err)
			}
		}
	}
	w := c.Listeners.Webhook
	if w.Enabled {
		if !cleanPath(w.CertFile) || len(w.ClientCAFiles) == 0 || len(w.ClientDNSNames) == 0 || !c.Inventory.Enabled {
			return errors.New("webhook requires loopback TLS, client trust/DNS names and Fleet inventory")
		}
		if err := addListener(w.Address, true); err != nil {
			return fmt.Errorf("webhook listener: %w", err)
		}
	}
	for _, f := range w.ClientCAFiles {
		if !cleanPath(f) {
			return errors.New("webhook client CA paths must be absolute and clean")
		}
	}
	b := c.Listeners.Broker
	if b.Enabled && (!cleanPath(b.CertFile) || b.Username == "" || b.Provisioner == "" || !httpsURL(b.SCEPURL) || !c.Inventory.Fleet.ManagedCertificates) {
		return errors.New("broker requires distinct TLS listener, credentials, HTTPS SCEP URL and managed certificate inventory")
	}
	if b.Enabled {
		if err := addListener(b.Address, false); err != nil {
			return fmt.Errorf("broker listener: %w", err)
		}
	}
	if c.Inventory.Provider != "fleet" {
		return errors.New("inventory provider must be fleet; Okta/Jamf support was removed")
	}
	if c.Inventory.Enabled && (!httpsURL(c.Inventory.Fleet.BaseURL) || !duration(c.Inventory.Fleet.Timeout, time.Minute)) {
		return errors.New("Fleet inventory requires HTTPS base_url and bounded timeout")
	}
	if c.Inventory.Enabled && c.Inventory.Fleet.ManagedCertificates && !cleanPath(c.Inventory.Fleet.ClientCAFile) {
		return errors.New("Fleet managed collection requires explicit client_ca_file trust bundle")
	}
	if !duration(c.Inventory.Fleet.PollInterval, 30*24*time.Hour) || c.Inventory.Fleet.PollInterval < time.Hour || !duration(c.Inventory.Fleet.MaxPendingAge, 30*24*time.Hour) {
		return errors.New("Fleet collection requires at least hourly polling and bounded pending age")
	}
	a := c.Policy.AttestedACME
	if a.Enabled && (!cleanPath(a.IssuerFile) || a.Provisioner == "" || !c.Inventory.Enabled || !c.Inventory.Fleet.ManagedCertificates || c.Policy.IdentityMode != "fingerprint") {
		return errors.New("attested ACME requires pinned issuer, exact provisioner, fingerprint mode and managed certificate inventory")
	}
	if len(c.Inventory.Fleet.ACMEProfileUUIDs) > 0 && !a.Enabled {
		return errors.New("ACME profile polling exemptions require verified attested ACME")
	}
	if c.Policy.IdentityMode != "fingerprint" && c.Policy.IdentityMode != "legacy-serial" {
		return errors.New("policy identity_mode must be fingerprint or legacy-serial")
	}
	if !duration(c.Policy.InventoryMaxAge, 24*time.Hour) || !duration(c.Policy.CertificateMaxAge, 30*24*time.Hour) || !duration(c.Policy.HandoffMaxAge, 120*time.Second) || !duration(c.Policy.ClassMaxAge, 30*24*time.Hour) {
		return errors.New("policy freshness bounds invalid")
	}
	if c.Policy.FallbackVLAN < 0 || c.Policy.FallbackVLAN > 4094 {
		return errors.New("policy fallback VLAN must be unset or 1-4094")
	}
	providers := map[string]NetworkProvider{}
	for _, p := range c.Network.Providers {
		if p.ID == "" || providers[p.ID].ID != "" {
			return errors.New("network provider IDs must be nonempty and unique")
		}
		if p.Kind != "unifi" && p.Kind != "meraki" {
			return errors.New("network provider kind must be unifi or meraki; Okta/Jamf support was removed")
		}
		if !httpsURL(p.BaseURL) || len(p.Scopes) == 0 || (p.Timeout != 0 && !duration(p.Timeout, time.Minute)) {
			return errors.New("network provider requires HTTPS base_url, scopes and bounded timeout")
		}
		if err := p.Credential.Validate("network provider credential", true); err != nil {
			return err
		}
		providers[p.ID] = p
	}
	if err := validateNetworkDetails(c); err != nil {
		return err
	}
	locations := map[string]Location{}
	sites := map[string]bool{}
	for _, l := range c.Network.Locations {
		if l.ID == "" || locations[l.ID].ID != "" || l.SiteID == "" || providers[l.ProviderID].ID == "" || sites[l.ProviderID+"\x00"+l.SiteID] {
			return errors.New("network location requires unique ID, known provider and unambiguous provider/site mapping")
		}
		locations[l.ID] = l
		sites[l.ProviderID+"\x00"+l.SiteID] = true
	}
	rules := map[string]bool{}
	for _, r := range c.Policy.Rules {
		key := r.GroupID + "\x00" + r.LocationID
		if r.GroupID == "" || locations[r.LocationID].ID == "" || r.VLAN < 1 || r.VLAN > 4094 || rules[key] || !locations[r.LocationID].VLANEnabled {
			return errors.New("policy rules require group, known location, unique group/location and VLAN 1-4094")
		}
		rules[key] = true
	}
	clients := map[string]bool{}
	var ranges []netip.Prefix
	for _, r := range c.RadiusClients {
		l := locations[r.LocationID]
		if r.ID == "" || clients[r.ID] || l.ID == "" || len(r.CIDRs) == 0 || (r.Medium != "wifi" && r.Medium != "wired") || (r.Medium == "wired" && l.VLANEnabled) {
			return errors.New("RADIUS client requires unique ID, known location, CIDRs; wired VLAN selection remains disabled")
		}
		if l.VLANEnabled && (r.SignalingProfile != providers[l.ProviderID].Kind+"-numeric") {
			return errors.New("enabled VLAN location requires the configured provider numeric signaling profile")
		}
		if r.SignalingProfile != "" && r.SignalingProfile != "unifi-numeric" && r.SignalingProfile != "meraki-numeric" {
			return errors.New("unsupported RADIUS signaling profile")
		}
		if err := r.Secret.Validate("radius client secret", true); err != nil {
			return err
		}
		clients[r.ID] = true
		for _, s := range r.CIDRs {
			p, e := netip.ParsePrefix(s)
			if e != nil || p.Bits() == 0 || p != p.Masked() || p.Addr().Is4In6() {
				return errors.New("RADIUS client CIDRs must be canonical, bounded prefixes")
			}
			for _, other := range ranges {
				if p.Overlaps(other) {
					return errors.New("RADIUS client CIDRs overlap")
				}
			}
			ranges = append(ranges, p)
		}
	}
	t := c.Telemetry
	if t.Transport != "http" && t.Transport != "grpc" {
		return errors.New("telemetry transport must be http or grpc")
	}
	if math.IsNaN(t.TraceSampleRatio) || t.TraceSampleRatio < 0 || t.TraceSampleRatio > 1 || t.QueueSize < 1 || t.QueueSize > 65536 || !duration(t.Timeout, time.Minute) || !duration(t.ShutdownTimeout, time.Minute) {
		return errors.New("telemetry sampling, queue or timeout out of bounds")
	}
	for index, endpoint := range []string{t.BusinessEndpoint, t.Endpoint} {
		if index == 1 && !t.Enabled {
			continue
		}
		u, e := url.Parse(endpoint)
		if e != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
			return errors.New("telemetry requires a credential-free HTTP(S) endpoint")
		}
		if u.Scheme == "http" {
			ip, e := netip.ParseAddr(u.Hostname())
			if e != nil || !ip.IsLoopback() {
				return errors.New("plaintext telemetry is restricted to numeric loopback")
			}
		}
	}
	if c.CA.Provider != "step-ca" {
		return errors.New("CA provider must be step-ca; Okta support was removed")
	}
	if c.CA.URL != "" && !httpsURL(c.CA.URL) {
		return errors.New("CA URL must use HTTPS without credentials")
	}
	s := c.Schedules
	for _, d := range []time.Duration{s.Inventory, s.Certificates, s.Sites, s.Sources, s.Metrics} {
		if !duration(d, 30*24*time.Hour) {
			return errors.New("schedule durations must be positive and bounded")
		}
	}
	if s.AccountingWorkers < 1 || s.AccountingWorkers > 32 || s.ExportWorkers < 1 || s.ExportWorkers > 32 {
		return errors.New("worker count must be 1-32")
	}
	if !duration(c.Network.MetadataMaxAge, 24*time.Hour) {
		return errors.New("network metadata age out of bounds")
	}
	if !duration(c.Network.Discovery.MaxAge, 7*24*time.Hour) {
		return errors.New("source discovery age out of bounds")
	}
	for _, path := range []string{c.Paths.StateDir, c.Paths.CacheDir, c.Paths.HandoffDir, c.Paths.InventoryFile, c.Paths.MetadataFile, c.Paths.AuthLogDir, c.Paths.AccountingSpoolDir, c.Paths.DowngradeGuardFile, c.Paths.LegacyStateDir, c.Backends.RadiusBinary, c.Backends.RadiusConfigDir, c.Backends.StepBinary, c.Backends.CollectorConfigFile} {
		if !cleanPath(path) {
			return errors.New("runtime and backend paths must be absolute and clean")
		}
	}
	for _, path := range append(append([]string{}, c.CA.RootFiles...), c.CA.IntermediateFiles...) {
		if !cleanPath(path) {
			return errors.New("CA certificate paths must be absolute and clean")
		}
	}
	for _, path := range []string{c.Telemetry.CAFile, c.CA.ConfigFile, c.CA.ServerCertFile, c.CA.ReadinessFile, c.Policy.AttestedACME.IssuerFile, c.Inventory.Fleet.CacheFile, c.Inventory.Fleet.ClientCAFile, c.Network.Discovery.CandidateFile} {
		if path != "" && !cleanPath(path) {
			return errors.New("optional paths must be absolute and clean")
		}
	}
	return nil
}
