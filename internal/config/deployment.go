package config

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

// Deployment binds a parallel installation to its physical instances and its
// immutable accounting collection epoch. Activation is never a configuration
// flag: only the authenticated handoff can authorize production work.
type Deployment struct {
	DestinationPrimaryKey   string    `yaml:"destination_primary_key"`
	DestinationSecondaryKey string    `yaml:"destination_secondary_key"`
	SourcePrimaryKey        string    `yaml:"source_primary_key"`
	SourceSecondaryKey      string    `yaml:"source_secondary_key"`
	Mode                    string    `yaml:"mode"`
	ID                      string    `yaml:"id"`
	Instance                string    `yaml:"instance"`
	SourceID                string    `yaml:"source_id"`
	SourcePrimary           string    `yaml:"source_primary"`
	SourceSecondary         string    `yaml:"source_secondary"`
	CollectionEpoch         time.Time `yaml:"collection_epoch"`
}

func (c Config) ValidateDeployment() error {
	d := c.Deployment
	if d == (Deployment{}) {
		return nil
	}
	for _, pin := range []string{d.SourcePrimaryKey, d.SourceSecondaryKey, d.DestinationPrimaryKey, d.DestinationSecondaryKey} {
		if pin != "" && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(pin) {
			return errors.New("deployment receipt pins must be Ed25519 public keys")
		}
	}
	label := regexp.MustCompile(`^[a-z][a-z0-9-]{0,38}[a-z0-9]$`)
	instance := regexp.MustCompile(`^[a-z][a-z0-9-]{0,61}[a-z0-9]$`)
	if d.Mode != "parallel" || !label.MatchString(d.ID) || !label.MatchString(d.SourceID) || d.ID == d.SourceID {
		return errors.New("parallel deployment requires distinct explicit deployment identities")
	}
	if (c.InstanceID != "radius-primary" && c.InstanceID != "radius-secondary") || d.Instance != d.ID+strings.TrimPrefix(c.InstanceID, "radius") {
		return errors.New("physical instance must match the deployment and fixed logical role")
	}
	if !instance.MatchString(d.SourcePrimary) || !instance.MatchString(d.SourceSecondary) || d.SourcePrimary == d.SourceSecondary || d.SourcePrimary == d.Instance || d.SourceSecondary == d.Instance {
		return errors.New("parallel deployment requires distinct original source instances")
	}
	if d.CollectionEpoch.IsZero() || d.CollectionEpoch.Nanosecond() != 0 || d.CollectionEpoch.Format(time.RFC3339) != d.CollectionEpoch.UTC().Format(time.RFC3339) {
		return errors.New("parallel collection epoch requires UTC whole seconds")
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(c.StateTransition) {
		return errors.New("parallel deployment requires an explicit protected transition")
	}
	if c.Database.Name != "cloud8021x_"+strings.ReplaceAll(d.ID, "-", "_") {
		return errors.New("parallel database must belong exclusively to this deployment")
	}
	if c.Network.Discovery.Enabled && c.Network.Discovery.Firewall.Node != d.Instance {
		return errors.New("parallel source firewall must target only this physical green instance")
	}
	return nil
}

func (c Config) Parallel() bool { return c.Deployment.Mode == "parallel" }

// ValidateHandoffPins is stricter than initial configuration validation so the
// public keys can be enrolled before freezing the final immutable deployment.
func (c Config) ValidateHandoffPins() error {
	if !c.Parallel() {
		return errors.New("parallel handoff configuration required")
	}
	if err := c.ValidateDeployment(); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, pin := range []string{c.Deployment.SourcePrimaryKey, c.Deployment.SourceSecondaryKey, c.Deployment.DestinationPrimaryKey, c.Deployment.DestinationSecondaryKey} {
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(pin) || seen[pin] {
			return errors.New("four distinct reviewed physical host receipt pins required before capture/preparation")
		}
		seen[pin] = true
	}
	return nil
}
