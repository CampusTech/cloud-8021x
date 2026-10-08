package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/meraki"
	"github.com/CampusTech/cloud-8021x/internal/adapters/unifi"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	networkjob "github.com/CampusTech/cloud-8021x/internal/jobs/network"
	"github.com/CampusTech/cloud-8021x/internal/network"
	"github.com/CampusTech/cloud-8021x/internal/privileged/sources"
)

// NetworkRegistryFromConfig is the sole vendor construction boundary. Cached
// inventory never replaces the uncached optional source-verification capability.
func NetworkRegistryFromConfig(cfg config.Config, dry bool, hc *http.Client) (*network.Registry, error) {
	entries := []network.Registration{}
	for _, p := range cfg.Network.Providers {
		raw, e := readInventoryFile(p.Credential.File, true, 4096)
		if e != nil {
			return nil, e
		}
		key := string(bytes.TrimSpace(raw))
		identityBytes, _ := json.Marshal(struct {
			Config config.NetworkProvider
			Key    string
		}{p, key})
		identityHash := sha256.Sum256(identityBytes)
		r := network.Registration{Identity: hex.EncodeToString(identityHash[:]), ID: p.ID, Scope: domain.InventoryScope{ProviderID: p.ID, IDs: append([]string(nil), p.Scopes...)}}
		switch p.Kind {
		case "unifi":
			if p.ConsoleID == "" {
				return nil, errors.New("UniFi inventory requires pinned console_id")
			}
			c, e := unifi.New(p.ID, p.BaseURL, key, hc, p.Timeout, nil)
			if e != nil {
				return nil, e
			}
			c.ConsoleID = p.ConsoleID
			r.Inventory = c
			r.Signaler = c
			r.Discovery = c
		case "meraki":
			c, e := meraki.New(p.ID, p.OrganizationID, p.BaseURL, key, hc, p.Timeout)
			if e != nil {
				return nil, e
			}
			r.Inventory = c
			r.Signaler = c
		default:
			return nil, errors.New("unsupported network provider")
		}
		if !dry && p.CacheFile != "" {
			b, _ := json.Marshal(struct {
				Config config.NetworkProvider
				Key    string
			}{p, key})
			hash := sha256.Sum256(b)
			r.Inventory = &network.CachedProvider{Provider: r.Inventory, Key: hex.EncodeToString(hash[:]), Path: p.CacheFile, MaxAge: cfg.Schedules.Sites}
		}
		entries = append(entries, r)
	}
	return network.NewRegistry(entries)
}
func NetworkServiceFromConfig(cfg config.Config, store *network.Store, dry bool, hc *http.Client) (*networkjob.Service, error) {
	r, e := NetworkRegistryFromConfig(cfg, dry, hc)
	if e != nil {
		return nil, e
	}
	identities := []string{}
	for _, entry := range r.Entries {
		identities = append(identities, entry.Identity)
	}
	data, _ := json.Marshal(identities)
	hash := sha256.Sum256(data)
	return &networkjob.Service{Key: hex.EncodeToString(hash[:]), Registry: r, Store: store, Path: cfg.Paths.MetadataFile}, nil
}
func SourceConfig(cfg config.Config) (sources.Config, error) {
	out := sources.Config{MaxAge: cfg.Network.Discovery.MaxAge}
	for _, client := range cfg.RadiusClients {
		b := sources.Binding{ClientID: client.ID, LocationID: client.LocationID, Medium: client.Medium, SignalingProfile: client.SignalingProfile, SecretFile: client.Secret.File, StaticCIDRs: append([]string(nil), client.CIDRs...)}
		for _, binding := range cfg.Network.Discovery.Bindings {
			if binding.ClientID == client.ID {
				for _, p := range cfg.Network.Providers {
					if p.ID == binding.ProviderID {
						b.ProviderID = p.ID
						b.ProviderOrigin = p.BaseURL
						b.ConsoleID = p.ConsoleID
					}
				}
			}
		}
		out.Bindings = append(out.Bindings, b)
	}
	return out, out.Validate()
}

// RootVerifier constructs only configured UniFi clients and performs fresh HTTPS
// hosts reads. It ignores inventory caches and all URLs/IDs supplied by candidates.
type RootVerifier struct {
	Providers map[string]domain.SourceDiscoveryProvider
}

func (v RootVerifier) Verify(ctx context.Context, bindings []sources.Binding) ([]domain.SourceCandidate, error) {
	result := []domain.SourceCandidate{}
	for _, b := range bindings {
		if b.ConsoleID == "" {
			continue
		}
		p := v.Providers[b.ProviderID]
		if p == nil {
			return nil, errors.New("configured source verifier unavailable")
		}
		rows, e := p.DiscoverSources(ctx, domain.InventoryScope{ProviderID: b.ProviderID, IDs: []string{b.ConsoleID}})
		if e != nil {
			return nil, e
		}
		result = append(result, rows...)
	}
	return result, nil
}
func SourceDiscoveryFromConfig(cfg config.Config, hc *http.Client) ([]networkjob.Discovery, error) {
	out := []networkjob.Discovery{}
	for _, binding := range cfg.Network.Discovery.Bindings {
		found := false
		for _, p := range cfg.Network.Providers {
			if p.ID != binding.ProviderID {
				continue
			}
			if p.Kind != "unifi" || p.ConsoleID == "" {
				return nil, errors.New("source discovery unsupported")
			}
			key, e := readInventoryFile(p.Credential.File, true, 4096)
			if e != nil {
				return nil, e
			}
			c, e := unifi.New(p.ID, p.BaseURL, string(bytes.TrimSpace(key)), hc, p.Timeout, nil)
			if e != nil {
				return nil, e
			}
			c.ConsoleID = p.ConsoleID
			out = append(out, networkjob.Discovery{Provider: c, Scope: domain.InventoryScope{ProviderID: p.ID, IDs: []string{p.ConsoleID}}})
			found = true
		}
		if !found {
			return nil, errors.New("configured source provider unavailable")
		}
	}
	return out, nil
}

// SourceDependencies is installed by Task8. Root credential access and actual
// service/firewall clients belong to that boundary, never to the daemon runtime.
type SourceDependencies func(context.Context, config.Config) (sources.Verifier, sources.Operations, error)

func applySources(ctx context.Context, o RunOptions, dependencies SourceDependencies) error {
	if os.Geteuid() != 0 || o.ConfigFile != privilegedConfigFile {
		return errors.New("sources apply requires root and the fixed protected application configuration")
	}
	if dependencies == nil {
		return errors.New("privileged source installation dependencies unavailable")
	}
	cfg, e := readProtectedSourceConfig()
	if e != nil {
		return e
	}
	if e = cfg.Validate(); e != nil {
		return e
	}
	if !cfg.Network.Discovery.Enabled {
		return errors.New("source discovery is disabled")
	}
	sourceConfig, e := SourceConfig(cfg)
	if e != nil {
		return e
	}
	owner, e := user.Lookup(cfg.RuntimeUser)
	if e != nil {
		return errors.New("dedicated source producer account unavailable")
	}
	uid, e := strconv.Atoi(owner.Uid)
	if e != nil || uid <= 0 {
		return errors.New("invalid source producer account")
	}
	candidates, e := sources.ReadCandidate(cfg.Network.Discovery.CandidateFile, uid)
	if e != nil {
		return e
	}
	if e = checkSourceDigest(candidates, o.SourceCandidateSHA256); e != nil {
		return e
	}
	verify, ops, e := dependencies(ctx, cfg)
	if e != nil {
		return e
	}
	apply := func() error {
		bounded, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		plan, e := (&sources.Applier{Config: sourceConfig, Verifier: verify, Operations: ops}).Apply(bounded, candidates, o.DryRun)
		if e != nil {
			return e
		}
		if o.Output != nil {
			_, e = fmt.Fprintf(o.Output, "Validated %d discovered client entries and %d source ranges (dry-run=%t).\n", len(plan.Clients), len(plan.SourceRanges), o.DryRun)
			if e == nil && o.DryRun {
				for _, client := range plan.Clients {
					_, e = fmt.Fprintf(o.Output, "Client %s at %s: %v\n", client.ClientID, client.LocationID, client.CIDRs)
					if e != nil {
						break
					}
				}
				if e == nil {
					_, e = fmt.Fprintf(o.Output, "Fixed node %s firewall: source ranges %v; disabled=%t. No files or services changed.\n", cfg.Network.Discovery.Firewall.Node, plan.SourceRanges, plan.Disabled)
				}
			}
		}
		return e
	}
	if o.DryRun {
		return apply()
	}
	return network.WithPrivateLock(ctx, filepath.Join(filepath.Dir(sources.ClientsFile), "apply.lock"), apply)
}

func checkSourceDigest(candidates []domain.SourceCandidate, expected string) error {
	if expected == "" {
		return nil
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(expected) {
		return errors.New("invalid claimed source candidate digest")
	}
	data, e := json.Marshal(candidates)
	if e != nil {
		return errors.New("invalid source candidate")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != expected {
		return errors.New("source candidate changed since durable claim")
	}
	return nil
}
