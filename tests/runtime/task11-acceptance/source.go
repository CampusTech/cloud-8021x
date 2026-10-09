package main

import (
	"bytes"
	"errors"
	"slices"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
)

const syntheticDevice = "11111111-2222-4333-8444-555555555555"

func validateSourceScope(c config.Config) error {
	if c.Deployment != (config.Deployment{}) || (c.Hostname != "task11-blue-primary" && c.Hostname != "task11-blue-secondary") || c.InstanceID != roleOf(c.Hostname) || c.Policy.IdentityMode != "fingerprint" || c.Policy.AttestedACME.Enabled || c.Policy.FallbackVLAN != 0 || c.Network.Discovery.Enabled || c.Paths.InventoryFile != "/etc/freeradius/3.0/device-policy-cache.json" || c.Policy.ClassSigningKey.File != "/run/radius-accounting-key" || c.Listeners.Policy.Address != "127.0.0.1:9082" || c.Paths.HandoffDir != "/run/radius-certificate-bindings" || c.Paths.DowngradeGuardFile != "/var/lib/cloud-8021x/fingerprint-enforced" {
		return errors.New("synthetic source requires fixed original fingerprint/cache/Class/loopback boundaries")
	}
	if len(c.RadiusClients) != 1 || c.RadiusClients[0].ID != "task11-nas" || !slices.Equal(c.RadiusClients[0].CIDRs, []string{"10.203.11.40/32"}) || c.RadiusClients[0].LocationID != "task11" || c.RadiusClients[0].Medium != "wifi" || c.RadiusClients[0].SignalingProfile != "unifi-numeric" {
		return errors.New("only fixed private synthetic NAS allowed")
	}
	if len(c.Policy.Rules) != 1 || c.Policy.Rules[0] != (config.VLANRule{GroupID: "fleet:1", LocationID: "task11", VLAN: 120}) {
		return errors.New("only fixed synthetic device group/VLAN rule allowed")
	}
	return nil
}
func validateSourceCache(raw []byte) error {
	s, err := domain.DecodeSnapshot(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	if s.Version != 2 || len(s.Certificates) != 1 || len(s.Identities) != 1 || len(s.HardwareSerials) != 0 || s.Identities[syntheticDevice] == nil {
		return errors.New("source cache must contain the sole enrolled synthetic fingerprint identity")
	}
	for _, rec := range s.Certificates {
		if rec == nil || string(rec.DeviceID) != "fleet:1" || !rec.Enrolled || rec.ObservedAt == nil || !slices.Equal(rec.Groups, []domain.GroupID{"fleet:1"}) {
			return errors.New("source certificate identity is outside the fixture allowlist")
		}
	}
	return nil
}
