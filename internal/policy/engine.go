// Package policy authorizes only local, provider-neutral inventory snapshots.
package policy

import (
	"context"
	"errors"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/identity"
)

type IdentityMode string

const (
	FingerprintMode  IdentityMode = "fingerprint"
	LegacySerialMode IdentityMode = "legacy-serial"
)

type Rule struct {
	GroupID    domain.GroupID
	LocationID domain.LocationID
	VLAN       int
}
type Location struct {
	ID          domain.LocationID
	VLANEnabled bool
}
type Config struct {
	IdentityMode      IdentityMode
	InventoryMaxAge   time.Duration
	CertificateMaxAge time.Duration
	AttestedACME      bool
	Locations         []Location
	Rules             []Rule
	FallbackVLAN      int
}
type Engine struct {
	config    Config
	locations map[domain.LocationID]Location
	rules     map[domain.LocationID]map[domain.GroupID]int
}

func New(cfg Config) (*Engine, error) {
	if cfg.IdentityMode != FingerprintMode && cfg.IdentityMode != LegacySerialMode {
		return nil, errors.New("unsupported policy identity mode")
	}
	if cfg.InventoryMaxAge <= 0 || cfg.CertificateMaxAge <= 0 || cfg.FallbackVLAN < 0 || cfg.FallbackVLAN > 4094 || len(cfg.Locations) == 0 {
		return nil, errors.New("invalid policy bounds or locations")
	}
	if cfg.AttestedACME && cfg.IdentityMode != FingerprintMode {
		return nil, errors.New("attestation requires fingerprint mode")
	}
	e := &Engine{config: cfg, locations: map[domain.LocationID]Location{}, rules: map[domain.LocationID]map[domain.GroupID]int{}}
	e.config.Locations = append([]Location(nil), cfg.Locations...)
	e.config.Rules = append([]Rule(nil), cfg.Rules...)
	for _, l := range cfg.Locations {
		if l.ID == "" || e.locations[l.ID].ID != "" {
			return nil, errors.New("duplicate or missing location")
		}
		e.locations[l.ID] = l
	}
	for _, r := range cfg.Rules {
		l, ok := e.locations[r.LocationID]
		if !ok || !l.VLANEnabled || r.GroupID == "" || !domain.ValidVLAN(r.VLAN) {
			return nil, errors.New("invalid VLAN rule or rule conflicts with opted-out location")
		}
		if e.rules[r.LocationID] == nil {
			e.rules[r.LocationID] = map[domain.GroupID]int{}
		}
		if _, ok := e.rules[r.LocationID][r.GroupID]; ok {
			return nil, errors.New("duplicate VLAN rule")
		}
		e.rules[r.LocationID][r.GroupID] = r.VLAN
	}
	return e, nil
}
func (e *Engine) Config() Config {
	cfg := e.config
	cfg.Locations = append([]Location(nil), cfg.Locations...)
	cfg.Rules = append([]Rule(nil), cfg.Rules...)
	return cfg
}
func (e *Engine) ResolveCertificate(s domain.InventoryView, cert identity.VerifiedCertificate, now time.Time) (*domain.DeviceRecord, error) {
	if e.config.IdentityMode != FingerprintMode || !cert.Valid() || s.SchemaVersion() != 2 || !domain.Fresh(s.Updated(), now, e.config.InventoryMaxAge) {
		return nil, errors.New("unverified certificate or unavailable/stale inventory")
	}
	var device *domain.DeviceRecord
	if serial := cert.AttestedSerial(); serial != "" {
		if !e.config.AttestedACME {
			return nil, errors.New("attested ACME identity disabled")
		}
		device = s.BySerial(serial)
	} else {
		device = s.ByCertificate(cert.Fingerprint())
		if device != nil && (device.ObservedAt == nil || !domain.Fresh(*device.ObservedAt, now, e.config.CertificateMaxAge)) {
			return nil, errors.New("certificate observation stale or missing")
		}
	}
	if device == nil || !device.Enrolled || device.Groups == nil || device.DeviceID == "" {
		return nil, errors.New("device unknown, ambiguous, malformed or unenrolled")
	}
	copy := *device
	copy.Groups = append([]domain.GroupID{}, device.Groups...)
	return &copy, nil
}
func (e *Engine) Authorize(ctx context.Context, s domain.InventoryView, cert identity.VerifiedCertificate, network domain.TrustedNetworkContext, now time.Time) (domain.Decision, error) {
	if err := ctx.Err(); err != nil {
		return domain.Decision{}, err
	}
	device, err := e.ResolveCertificate(s, cert, now)
	if err != nil {
		return domain.Decision{}, err
	}
	return e.selectVLAN(device, cert.Fingerprint(), network)
}

// AuthorizeLegacy is an explicit compatibility mode. It rechecks current inventory on
// every session (including resumed TLS) and never falls back from certificate mode.
func (e *Engine) AuthorizeLegacy(ctx context.Context, s domain.InventoryView, commonName string, network domain.TrustedNetworkContext, now time.Time) (domain.Decision, error) {
	if err := ctx.Err(); err != nil {
		return domain.Decision{}, err
	}
	if e.config.IdentityMode != LegacySerialMode || (s.SchemaVersion() != 1 && s.SchemaVersion() != 2) || !domain.Fresh(s.Updated(), now, e.config.InventoryMaxAge) {
		return domain.Decision{}, errors.New("legacy mode disabled or inventory stale")
	}
	name := domain.NormalizeIdentity(commonName)
	if name == "" || name == "cloud-8021x-inventory" {
		return domain.Decision{}, errors.New("missing or neutral inventory certificate identity")
	}
	device := s.ByIdentity(name)
	if device == nil || !device.Enrolled || device.Groups == nil || device.DeviceID == "" {
		return domain.Decision{}, errors.New("device unknown, ambiguous or unenrolled")
	}
	return e.selectVLAN(device, "", network)
}
func (e *Engine) selectVLAN(device *domain.DeviceRecord, fingerprint string, network domain.TrustedNetworkContext) (domain.Decision, error) {
	l, ok := e.locations[network.LocationID]
	if !ok || network.ClientID == "" || (network.Medium != domain.WiFi && network.Medium != domain.Wired) {
		return domain.Decision{}, errors.New("unknown trusted network context")
	}
	d := domain.Decision{DeviceID: device.DeviceID, Fingerprint: fingerprint}
	if !l.VLANEnabled || network.Medium == domain.Wired {
		return d, nil
	}
	selected := 0
	for _, group := range device.Groups {
		if vlan, ok := e.rules[l.ID][group]; ok {
			if selected != 0 && selected != vlan {
				return domain.Decision{}, errors.New("conflicting VLAN rules")
			}
			selected = vlan
		}
	}
	if selected == 0 {
		selected = e.config.FallbackVLAN
	}
	if !domain.ValidVLAN(selected) {
		return domain.Decision{}, errors.New("device has no VLAN assignment")
	}
	d.VLAN = &domain.VLANAssignment{ID: selected, LocationID: l.ID}
	return d, nil
}
