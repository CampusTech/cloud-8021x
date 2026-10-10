// Package policy is the local FreeRADIUS authorization transport boundary.
package policy

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
	"github.com/CampusTech/cloud-8021x/internal/adapters/network/signaling"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/identity"
	core "github.com/CampusTech/cloud-8021x/internal/policy"
	"github.com/CampusTech/cloud-8021x/internal/privileged/sources"
)

// All server fields are expanded from authenticated FreeRADIUS control/client state.
// Arrays preserve ambiguity; the backend must never collapse repeated values.
type ServerContext struct {
	ClientID string `json:"client_id"`
	SourceIP string `json:"source_ip"`
}
type Request struct {
	Server                 ServerContext `json:"server"`
	HandoffTokens          []string      `json:"handoff_tokens,omitempty"`
	CertificateCommonNames []string      `json:"certificate_common_names,omitempty"`
	CallingStations        []string      `json:"calling_stations,omitempty"`
	NASPortTypes           []string      `json:"nas_port_types,omitempty"`
}
type Result struct {
	Decision domain.Decision
	Network  domain.NetworkReply
	Class    string
}
type DecisionService interface {
	Decide(context.Context, Request) (Result, error)
}
type ServiceOptions struct {
	Engine    *core.Engine
	Snapshots *domain.SnapshotStore
	Trust     ClientResolver
	Handoff   identity.Handoff
	Signaling *signaling.Registry
	ClassKey  []byte
	Clock     func() time.Time
}
type LocalService struct{ options ServiceOptions }

func NewLocalService(o ServiceOptions) (*LocalService, error) {
	if o.Engine == nil || o.Snapshots == nil || o.Trust == nil || o.Signaling == nil {
		return nil, errors.New("missing local policy dependency")
	}
	if o.Engine.Config().IdentityMode == core.FingerprintMode && (len(o.ClassKey) < 32 || o.Handoff.Directory == "" || o.Handoff.MaxAge <= 0 || o.Handoff.MaxAge > identity.MaxHandoffAge) {
		return nil, errors.New("fingerprint policy requires private handoff and accounting key")
	}
	o.ClassKey = append([]byte(nil), o.ClassKey...)
	if o.Clock == nil {
		o.Clock = time.Now
	}
	return &LocalService{options: o}, nil
}
func (s *LocalService) Snapshots() *domain.SnapshotStore { return s.options.Snapshots }

// RefreshSources is a scheduled local state read, never part of Decide.
func (s *LocalService) RefreshSources() error {
	if source, ok := s.options.Trust.(*SourceTrust); ok {
		return source.Refresh()
	}
	return nil
}
func (s *LocalService) Decide(ctx context.Context, r Request) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	trusted, err := s.options.Trust.AuthenticatedClient(r.Server.ClientID, r.Server.SourceIP)
	if err != nil {
		return Result{}, err
	}
	// A configured wireless client is an upper bound, not proof of the medium.
	// Packet input may only remove VLAN privilege, never select a site/profile.
	if len(r.NASPortTypes) != 1 || r.NASPortTypes[0] != "19" {
		trusted.Medium = domain.Wired
	}
	now := s.options.Clock()
	snapshot := s.options.Snapshots.View()
	var decision domain.Decision
	fingerprintMode := s.options.Engine.Config().IdentityMode == core.FingerprintMode
	if fingerprintMode {
		if len(r.HandoffTokens) != 1 || len(r.CallingStations) != 1 || len(r.CertificateCommonNames) != 0 {
			return Result{}, errors.New("missing or ambiguous private certificate binding/station")
		}
		cert, err := s.options.Handoff.Consume(r.HandoffTokens[0], now)
		if err != nil {
			return Result{}, err
		}
		decision, err = s.options.Engine.Authorize(ctx, snapshot, cert, trusted, now)
		if err != nil {
			return Result{}, err
		}
	} else {
		if len(r.CertificateCommonNames) != 1 || len(r.HandoffTokens) != 0 {
			return Result{}, errors.New("missing or ambiguous server TLS common name")
		}
		decision, err = s.options.Engine.AuthorizeLegacy(ctx, snapshot, r.CertificateCommonNames[0], trusted, now)
		if err != nil {
			return Result{}, err
		}
	}
	result := Result{Decision: decision}
	if decision.VLAN != nil {
		result.Network, err = s.options.Signaling.Encode(ctx, *decision.VLAN, trusted)
		if err != nil {
			return Result{}, err
		}
	}
	if fingerprintMode {
		var vlan *int
		if decision.VLAN != nil {
			id := decision.VLAN.ID
			vlan = &id
		}
		result.Class, err = binding.Issue(s.options.ClassKey, binding.Attribution{DeviceID: decision.DeviceID, Fingerprint: decision.Fingerprint, VLAN: vlan}, string(trusted.LocationID), r.CallingStations[0], now)
		if err != nil {
			return Result{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	return result, nil
}

// FromConfig constructs the complete local HTTP policy service for daemon orchestration.
// It reads local files only. The returned store is refreshed by background inventory jobs.
func FromConfig(cfg config.Config, registry *signaling.Registry) (*LocalService, *Handler, error) {
	if err := cfg.Validate(); err != nil {
		return nil, nil, err
	}
	mode := core.IdentityMode(cfg.Policy.IdentityMode)
	if err := identity.CheckDowngradeGuard(cfg.Paths.DowngradeGuardFile, mode == core.FingerprintMode, false); err != nil {
		return nil, nil, err
	}
	pcfg := core.Config{IdentityMode: mode, InventoryMaxAge: cfg.Policy.InventoryMaxAge, CertificateMaxAge: cfg.Policy.CertificateMaxAge, AttestedACME: cfg.Policy.AttestedACME.Enabled, FallbackVLAN: cfg.Policy.FallbackVLAN}
	for _, l := range cfg.Network.Locations {
		pcfg.Locations = append(pcfg.Locations, core.Location{ID: domain.LocationID(l.ID), VLANEnabled: l.VLANEnabled})
	}
	for _, r := range cfg.Policy.Rules {
		pcfg.Rules = append(pcfg.Rules, core.Rule{GroupID: domain.GroupID(r.GroupID), LocationID: domain.LocationID(r.LocationID), VLAN: r.VLAN})
	}
	engine, err := core.New(pcfg)
	if err != nil {
		return nil, nil, err
	}
	sourceConfig, err := sources.FromConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	trust, err := NewSourceTrust(sourceConfig)
	if err != nil {
		return nil, nil, err
	}
	// Missing/stale dynamic state never prevents static-client construction.
	_ = trust.Refresh()
	file, err := os.Open(cfg.Paths.InventoryFile)
	if err != nil {
		return nil, nil, errors.New("local inventory unavailable")
	}
	snapshot, err := domain.DecodeSnapshot(file)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return nil, nil, errors.New("invalid local inventory")
	}
	store := new(domain.SnapshotStore)
	if err := store.Set(snapshot); err != nil {
		return nil, nil, err
	}
	key, err := binding.ReadKey(cfg.Policy.ClassSigningKey.File)
	if err != nil {
		return nil, nil, err
	}
	token, err := readLocalToken(cfg.Listeners.Policy.Token.File)
	if err != nil {
		return nil, nil, err
	}
	if registry == nil {
		registry, err = signaling.Builtins()
		if err != nil {
			return nil, nil, err
		}
	}
	service, err := NewLocalService(ServiceOptions{Engine: engine, Snapshots: store, Trust: trust, Handoff: identity.Handoff{Directory: cfg.Paths.HandoffDir, MaxAge: cfg.Policy.HandoffMaxAge}, Signaling: registry, ClassKey: key})
	if err != nil {
		return nil, nil, err
	}
	handler, err := NewHandler(HTTPOptions{Token: token, MaxConcurrency: cfg.Listeners.Policy.MaxConcurrency, MaxBodyBytes: cfg.Listeners.Policy.MaxBodyBytes, Timeout: cfg.Listeners.Policy.Timeout, Service: service})
	return service, handler, err
}

// AttributionInput is for native event adapters only. Count fields preserve duplicate
// ambiguity even when SQL intake can store just one scalar value. Receipt is original.
type AttributionInput struct {
	Classes      []string
	ClassCount   int
	Stations     []string
	StationCount int
	LocationID   domain.LocationID
	Receipt      time.Time
}

func VerifyAttribution(key []byte, input AttributionInput, maxAge time.Duration) *binding.Attribution {
	if input.ClassCount != 1 || len(input.Classes) != 1 || input.StationCount != 1 || len(input.Stations) != 1 {
		return nil
	}
	return binding.Verify(key, input.Classes, string(input.LocationID), input.Stations, input.Receipt, maxAge)
}
