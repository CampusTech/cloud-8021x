// Package config loads webhook configuration from the environment (Cloud Run
// injects PORT; secrets come from Secret Manager via env). Missing required
// values are a startup error — we never run half-configured.
package config

import (
	"errors"
	"os"
	"time"
)

type Config struct {
	Port          string
	SigningSecret string
	FleetBaseURL  string
	FleetToken    string
	AllowLabel    string // empty = no label gate
	FleetTimeout  time.Duration
}

func Load() (*Config, error) {
	c := &Config{
		Port:          envOr("PORT", "8080"),
		SigningSecret: os.Getenv("WEBHOOK_SIGNING_SECRET"),
		FleetBaseURL:  os.Getenv("FLEET_API_BASE_URL"),
		FleetToken:    os.Getenv("FLEET_API_TOKEN"),
		AllowLabel:    os.Getenv("ALLOW_LABEL"),
		FleetTimeout:  5 * time.Second,
	}
	if c.SigningSecret == "" || c.FleetBaseURL == "" || c.FleetToken == "" {
		return nil, errors.New("WEBHOOK_SIGNING_SECRET, FLEET_API_BASE_URL, and FLEET_API_TOKEN are required")
	}
	return c, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
