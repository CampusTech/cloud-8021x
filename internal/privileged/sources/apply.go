// Package sources implements the fixed privileged source transaction. Candidate
// bytes are untrusted; only fresh independent controller verification permits I/O.
package sources

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"sort"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/network"
)

type Binding struct {
	ProviderID, ProviderOrigin, ConsoleID, ClientID, LocationID, Medium, SignalingProfile, SecretFile string
	StaticCIDRs                                                                                       []string
}
type Config struct {
	MaxAge   time.Duration
	Bindings []Binding
}
type Verifier interface {
	Verify(context.Context, []Binding) ([]domain.SourceCandidate, error)
}
type ClientSources struct {
	ObservedAt, MaxAgeSeconds                                  int64
	ConfigSHA256                                               string
	ClientID, LocationID, Medium, SignalingProfile, SecretFile string
	CIDRs                                                      []string
}
type Plan struct {
	Clients      []ClientSources
	SourceRanges []string
	Disabled     bool
}
type State struct {
	ConfigSHA256 string
	Candidates   []domain.SourceCandidate
}
type FirewallState struct {
	SourceRanges []string
	Disabled     bool
}
type Backup struct {
	PreviousProof            []byte
	PreviousProofExist       bool
	Proof                    []byte
	ProofExist               bool
	Clients, State           []byte
	Firewall                 FirewallState
	ClientsExist, StateExist bool
}

// Operations is narrow and typed. Installation supplies fixed files, FreeRADIUS
// validation/service methods, and an exact node firewall resource. No commands,
// URLs, executable names or destination paths are accepted from the candidate.
type Operations interface {
	Snapshot(context.Context) (Backup, error)
	Install(context.Context, Plan) error
	Validate(context.Context) error
	Activate(context.Context) error
	Converge(context.Context, Plan) error
	Commit(context.Context, State) error
	Rollback(context.Context, Backup) error
}
type Applier struct {
	Config     Config
	Verifier   Verifier
	Operations Operations
	Now        func() time.Time
}

func key(p, s string) string { return p + "\x00" + s }
func (c Config) Validate() error {
	if c.MaxAge < time.Second || c.MaxAge > time.Hour || len(c.Bindings) == 0 || len(c.Bindings) > 128 {
		return errors.New("invalid source configuration")
	}
	clients := map[string]bool{}
	consoles := map[string]bool{}
	var ranges []struct {
		client string
		p      netip.Prefix
	}
	for _, b := range c.Bindings {
		if b.ClientID == "" || b.LocationID == "" || clients[b.ClientID] {
			return errors.New("ambiguous configured source client")
		}
		clients[b.ClientID] = true
		if b.ConsoleID != "" {
			k := key(b.ProviderID, b.ConsoleID)
			if b.ProviderID == "" || consoles[k] {
				return errors.New("ambiguous pinned source console")
			}
			consoles[k] = true
		}
		for _, raw := range b.StaticCIDRs {
			p, e := netip.ParsePrefix(raw)
			if e != nil || !safePrefix(p) || raw != p.String() {
				return errors.New("invalid static source prefix")
			}
			for _, r := range ranges {
				if r.client != b.ClientID && r.p.Overlaps(p) {
					return errors.New("source client ranges overlap")
				}
			}
			ranges = append(ranges, struct {
				client string
				p      netip.Prefix
			}{b.ClientID, p})
		}
	}
	return nil
}
func safePrefix(p netip.Prefix) bool {
	if !p.IsValid() || p.Addr().Is4In6() || p.Addr().Zone() != "" || p != p.Masked() || p.Bits() == 0 {
		return false
	}
	// Static IPv6 ranges have the same trust contract as the core TrustMap.
	// Dynamic discovery and firewall candidates remain public IPv4 /32 only.
	if p.Addr().Is6() {
		return true
	}
	for _, s := range []string{"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4"} {
		if p.Overlaps(netip.MustParsePrefix(s)) {
			return false
		}
	}
	return true
}
func canonical(candidates []domain.SourceCandidate, cfg Config, now time.Time) (map[string]domain.SourceCandidate, error) {
	return checkedCandidates(candidates, cfg, now, false)
}
func checkedCandidates(candidates []domain.SourceCandidate, cfg Config, now time.Time, allowExpired bool) (map[string]domain.SourceCandidate, error) {
	want := map[string]bool{}
	for _, b := range cfg.Bindings {
		if b.ConsoleID != "" {
			want[key(b.ProviderID, b.ConsoleID)] = true
		}
	}
	if len(candidates) != len(want) {
		return nil, errors.New("source evidence scope count mismatch")
	}
	out := map[string]domain.SourceCandidate{}
	for _, c := range candidates {
		k := key(c.ProviderID, c.SiteID)
		if !want[k] || out[k].ProviderID != "" || (!allowExpired && !domain.Fresh(c.ObservedAt, now, cfg.MaxAge)) || c.ObservedAt <= 0 || c.ObservedAt > domain.Unix(now) || math.IsNaN(float64(c.ObservedAt)) || math.IsInf(float64(c.ObservedAt), 0) || len(c.CIDRs) == 0 || len(c.CIDRs) > 16 {
			return nil, errors.New("source evidence missing, ambiguous or stale")
		}
		seen := map[string]bool{}
		copy := c
		copy.CIDRs = append([]string(nil), c.CIDRs...)
		for _, raw := range c.CIDRs {
			p, e := netip.ParsePrefix(raw)
			if e != nil || p.Bits() != 32 || !network.PublicIPv4(p.Addr()) || raw != p.String() || seen[raw] {
				return nil, errors.New("source candidate requires unique canonical public IPv4 /32s")
			}
			seen[raw] = true
		}
		sort.Strings(copy.CIDRs)
		out[k] = copy
	}
	return out, nil
}
func makePlan(cfg Config, proposed map[string]domain.SourceCandidate) (Plan, error) {
	p := Plan{Disabled: true}
	var ranges []struct {
		client string
		p      netip.Prefix
	}
	for _, b := range cfg.Bindings {
		for _, s := range b.StaticCIDRs {
			ranges = append(ranges, struct {
				client string
				p      netip.Prefix
			}{b.ClientID, netip.MustParsePrefix(s)})
		}
	}
	seen := map[string]bool{}
	for _, b := range cfg.Bindings {
		c := proposed[key(b.ProviderID, b.ConsoleID)]
		client := ClientSources{ClientID: b.ClientID, LocationID: b.LocationID, Medium: b.Medium, SignalingProfile: b.SignalingProfile, SecretFile: b.SecretFile}
		client.ObservedAt = int64(c.ObservedAt)
		client.MaxAgeSeconds = int64(cfg.MaxAge.Seconds())
		client.ConfigSHA256 = cfg.Identity()
		for _, raw := range c.CIDRs {
			prefix := netip.MustParsePrefix(raw)
			covered := false
			for _, r := range ranges {
				if !r.p.Overlaps(prefix) {
					continue
				}
				if r.client != b.ClientID {
					return Plan{}, errors.New("discovered source overlaps another configured client")
				}
				covered = true
			}
			ranges = append(ranges, struct {
				client string
				p      netip.Prefix
			}{b.ClientID, prefix})
			if !covered {
				client.CIDRs = append(client.CIDRs, raw)
			}
			if !seen[raw] {
				seen[raw] = true
				p.SourceRanges = append(p.SourceRanges, raw)
			}
		}
		if len(client.CIDRs) > 0 {
			p.Clients = append(p.Clients, client)
		}
	}
	sort.Strings(p.SourceRanges)
	p.Disabled = len(p.SourceRanges) == 0
	return p, nil
}
func (a *Applier) Apply(ctx context.Context, candidates []domain.SourceCandidate, dry bool) (Plan, error) {
	if e := ctx.Err(); e != nil {
		return Plan{}, e
	}
	if e := a.Config.Validate(); e != nil {
		return Plan{}, e
	}
	if a.Verifier == nil {
		return Plan{}, errors.New("authenticated root source verifier unavailable")
	}
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	proposed, e := canonical(candidates, a.Config, now)
	if e != nil {
		return Plan{}, e
	}
	evidence, e := a.Verifier.Verify(ctx, append([]Binding(nil), a.Config.Bindings...))
	if e != nil {
		return Plan{}, errors.New("authenticated root source verification failed")
	}
	trusted, e := canonical(evidence, a.Config, nowTime(a.Now))
	if e != nil {
		return Plan{}, e
	}
	for k, c := range proposed {
		if !reflect.DeepEqual(c.CIDRs, trusted[k].CIDRs) {
			return Plan{}, errors.New("candidate addresses disagree with authenticated pinned controller")
		}
	}
	plan, e := makePlan(a.Config, proposed)
	if e != nil {
		return Plan{}, e
	}
	if e = ctx.Err(); e != nil {
		return Plan{}, e
	}
	if a.Operations == nil {
		return Plan{}, errors.New("privileged source operations unavailable")
	}
	backup, e := a.Operations.Snapshot(ctx)
	if e != nil {
		return Plan{}, e
	}
	if dry {
		return plan, nil
	}
	rollback := func(cause error) (Plan, error) {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if e := a.Operations.Rollback(cleanup, backup); e != nil {
			return Plan{}, errors.New("source apply failed; rollback incomplete and reconciliation required")
		}
		return Plan{}, fmt.Errorf("source apply rolled back: %w", cause)
	}
	for _, step := range []func() error{func() error { return a.Operations.Install(ctx, plan) }, func() error { return a.Operations.Validate(ctx) }, func() error { return a.Operations.Activate(ctx) }, func() error { return a.Operations.Converge(ctx, plan) }} {
		if e = step(); e != nil {
			return rollback(e)
		}
	}
	// Recheck original observation ages after convergence, never stamp old candidates
	// with application time. Commit is the final freshness boundary.
	if _, e = canonical(candidates, a.Config, nowTime(a.Now)); e != nil {
		return rollback(e)
	}
	state := State{ConfigSHA256: a.Config.Identity()}
	for _, b := range a.Config.Bindings {
		if b.ConsoleID != "" {
			state.Candidates = append(state.Candidates, proposed[key(b.ProviderID, b.ConsoleID)])
		}
	}
	if e = a.Operations.Commit(ctx, state); e != nil {
		return rollback(e)
	}
	return plan, nil
}
func nowTime(now func() time.Time) time.Time {
	if now != nil {
		return now()
	}
	return time.Now()
}

// Allowed is a local expiry guard for Task6. The configured client/location is
// already authenticated; metadata/NAS/certificate fields cannot select it.
func Allowed(cfg Config, state State, clientID, source string, now time.Time) bool {
	a, e := netip.ParseAddr(source)
	if e != nil || a.Is4In6() || a.Zone() != "" {
		return false
	}
	for _, b := range cfg.Bindings {
		if b.ClientID != clientID {
			continue
		}
		for _, raw := range b.StaticCIDRs {
			p, e := netip.ParsePrefix(raw)
			if e == nil && p.Contains(a) {
				return true
			}
		}
		if state.ConfigSHA256 != cfg.Identity() {
			return false
		}
		for _, c := range state.Candidates {
			if c.ProviderID != b.ProviderID || c.SiteID != b.ConsoleID || b.ConsoleID == "" || !domain.Fresh(c.ObservedAt, now, cfg.MaxAge) {
				continue
			}
			for _, raw := range c.CIDRs {
				p, e := netip.ParsePrefix(raw)
				if e == nil && p.Bits() == 32 && p.Contains(a) && network.PublicIPv4(p.Addr()) {
					return true
				}
			}
		}
	}
	return false
}
func ReadCandidate(path string, owner int) ([]domain.SourceCandidate, error) {
	b, e := network.ReadPrivate(path, owner)
	if e != nil {
		return nil, e
	}
	var result []domain.SourceCandidate
	if e = domain.DecodeJSONStrict(b, &result); e != nil {
		return nil, errors.New("invalid source candidate JSON")
	}
	if len(result) > 128 {
		return nil, errors.New("too many source candidates")
	}
	return result, nil
}
func StateBytes(s State) ([]byte, error) { return json.Marshal(s) }

// ReadState authenticates root ownership at every path component. The daemon
// can read this non-secret 0644 state but cannot replace it or its ancestry.
func ReadState() (State, error) {
	data, e := network.ReadPublished(StateFile, 0)
	if e != nil {
		return State{}, e
	}
	var s State
	if domain.DecodeJSONStrict(data, &s) != nil || len(s.Candidates) > 128 || len(s.ConfigSHA256) != 64 {
		return State{}, errors.New("invalid applied source state")
	}
	return s, nil
}

// AuthenticatedClient is for the backend's already authenticated client ID and
// actual transport source, never packet NAS/site attributes. Task6 can use this
// alongside its static TrustMap without metadata or controller I/O.
func AuthenticatedClient(cfg Config, state State, clientID, source string, now time.Time) (domain.TrustedNetworkContext, error) {
	if !Allowed(cfg, state, clientID, source, now) {
		return domain.TrustedNetworkContext{}, errors.New("source is outside configured or fresh applied client ranges")
	}
	for _, b := range cfg.Bindings {
		if b.ClientID == clientID {
			return domain.TrustedNetworkContext{ClientID: b.ClientID, LocationID: domain.LocationID(b.LocationID), Medium: domain.NetworkMedium(b.Medium), SignalingProfile: b.SignalingProfile, SourceIP: source}, nil
		}
	}
	return domain.TrustedNetworkContext{}, errors.New("unknown authenticated client")
}

// Identity binds public applied state to protected origin, pins, client context,
// secret references and freshness bounds. No resolved secret enters the hash input.
func (c Config) Identity() string {
	data, _ := json.Marshal(c)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
