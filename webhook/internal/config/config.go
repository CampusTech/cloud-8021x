// Package config loads the loopback webhook configuration from the environment.
// Secrets come from Secret Manager via a protected systemd env file. Missing required
// values are a startup error — we never run half-configured.
package config

import (
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/CampusTech/cloud-8021x/webhook/internal/broker"
)

type Config struct {
	TLSCertFile              string
	TLSKeyFile               string
	Port                     string
	ClientCAFiles            string
	ClientDNSNames           string
	FleetBaseURL             string
	FleetToken               string
	AllowLabel               string // empty = no label gate
	SCEPChallengeSigningKey  string // server-only key; empty disables SCEP issuance
	FleetTimeout             time.Duration
	SCEPCertificateInventory bool
	SCEPBrokerPort           string
	SCEPBrokerUsername       string
	SCEPBrokerToken          string
	SCEPBrokerSCEPURL        string
	SCEPBrokerProvisioner    string
}

func Load() (*Config, error) {
	c := &Config{
		TLSCertFile:              envOr("WEBHOOK_TLS_CERT_FILE", "/etc/acme-authz-webhook/server.crt"),
		TLSKeyFile:               envOr("WEBHOOK_TLS_KEY_FILE", "/etc/acme-authz-webhook/server.key"),
		Port:                     envOr("PORT", "8080"),
		ClientCAFiles:            envOr("WEBHOOK_CLIENT_CA_FILES", "/etc/acme-authz-webhook/client-cas.pem"),
		ClientDNSNames:           os.Getenv("WEBHOOK_CLIENT_DNS_NAMES"),
		FleetBaseURL:             os.Getenv("FLEET_API_BASE_URL"),
		FleetToken:               os.Getenv("FLEET_API_TOKEN"),
		AllowLabel:               os.Getenv("ALLOW_LABEL"),
		SCEPChallengeSigningKey:  os.Getenv("SCEP_CHALLENGE_SIGNING_KEY"),
		FleetTimeout:             5 * time.Second,
		SCEPCertificateInventory: os.Getenv("SCEP_CERTIFICATE_INVENTORY") == "true",
		SCEPBrokerPort:           envOr("SCEP_BROKER_PORT", "9081"),
		SCEPBrokerUsername:       os.Getenv("SCEP_BROKER_USERNAME"),
		SCEPBrokerToken:          os.Getenv("SCEP_BROKER_TOKEN"),
		SCEPBrokerSCEPURL:        os.Getenv("SCEP_BROKER_SCEP_URL"),
		SCEPBrokerProvisioner:    os.Getenv("SCEP_BROKER_PROVISIONER"),
	}
	if c.ClientDNSNames == "" || c.FleetBaseURL == "" || c.FleetToken == "" {
		return nil, errors.New("WEBHOOK_CLIENT_DNS_NAMES, FLEET_API_BASE_URL, and FLEET_API_TOKEN are required")
	}
	if c.SCEPChallengeSigningKey != "" && len(c.SCEPChallengeSigningKey) < 32 {
		return nil, errors.New("SCEP_CHALLENGE_SIGNING_KEY must contain at least 32 bytes")
	}
	switch os.Getenv("SCEP_CERTIFICATE_INVENTORY") {
	case "", "false", "true":
	default:
		return nil, errors.New("SCEP_CERTIFICATE_INVENTORY must be true or false")
	}
	if c.SCEPCertificateInventory {
		if err := c.BrokerOptions().Validate(); err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(c.SCEPBrokerPort)
		if err != nil || port < 1 || port > 65535 || c.SCEPBrokerPort == c.Port {
			return nil, errors.New("SCEP_BROKER_PORT must be a valid port distinct from PORT")
		}
	}
	return c, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func (c *Config) BrokerOptions() broker.Options {
	return broker.Options{Username: c.SCEPBrokerUsername, Token: c.SCEPBrokerToken, SigningKey: c.SCEPChallengeSigningKey, SCEPURL: c.SCEPBrokerSCEPURL, Provisioner: c.SCEPBrokerProvisioner}
}
