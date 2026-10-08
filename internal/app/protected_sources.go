package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/freeradius/native"
	"github.com/CampusTech/cloud-8021x/internal/adapters/gcp"
	"github.com/CampusTech/cloud-8021x/internal/adapters/unifi"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
	"github.com/CampusTech/cloud-8021x/internal/privileged/sources"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
)

type protectedSecretValues map[string][]byte

func (v protectedSecretValues) ReadSecret(path string) ([]byte, error) {
	b, ok := v[path]
	if !ok {
		return nil, errors.New("unmapped protected source credential")
	}
	return append([]byte(nil), b...), nil
}

// protectedSources supplies the concrete fixed host/cloud backend. Task9 adds
// the per-node durable claim before calling this exact-candidate operation; the
// daemon never receives a sudo or generic service-control capability.
func protectedSources(ctx context.Context, cfg config.Config, o RunOptions) error {
	cfg, e := protectedConfiguration(cfg, o)
	if e != nil {
		return e
	}
	if e = cfg.Validate(); e != nil {
		return e
	}
	if e = cfg.ValidateBootstrap(); e != nil {
		return e
	}
	if !cfg.Network.Discovery.Enabled {
		return errors.New("source discovery disabled")
	}
	if o.DryRun {
		if o.Output == nil {
			return nil
		}
		return json.NewEncoder(o.Output).Encode(map[string]any{"dry_run": true, "steps": []string{"validate-candidate-digest", "independent-pinned-controller-verification", "shared-maintenance", "validate-native-configuration", "authenticated-peer-readiness", "scoped-firewall-convergence", "publish-original-observation-proof"}, "node": cfg.Network.Discovery.Firewall.Node, "candidate_sha256": o.SourceCandidateSHA256})
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(o.SourceCandidateSHA256) {
		return errors.New("root source application requires the exact candidate SHA256")
	}
	accounts, e := host.ReadAccounts()
	if e != nil {
		return e
	}
	values, e := host.CommittedCredentials(bootCredentialLayout(cfg, accounts))
	if e != nil {
		return e
	}
	cloud, e := gcp.NewRoot(cfg.Bootstrap.Project, cfg.Bootstrap.ProjectNumber)
	if e != nil {
		return e
	}
	repository, e := postgres.NewMigration(ctx, string(values[cfg.Database.MigrationDSN.File]), cfg.Database)
	if e != nil {
		return e
	}
	defer repository.Close()
	gate := postgres.MaintenanceGate{Store: repository}
	return gate.With(ctx, "sources-apply", func(ctx context.Context) error {
		verifier := RootVerifier{Providers: map[string]domain.SourceDiscoveryProvider{}}
		for _, p := range cfg.Network.Providers {
			if p.Kind != "unifi" || p.ConsoleID == "" {
				continue
			}
			client, e := unifi.New(p.ID, p.BaseURL, string(bytes.TrimSpace(values[p.Credential.File])), nil, p.Timeout, nil)
			if e != nil {
				return e
			}
			client.ConsoleID = p.ConsoleID
			verifier.Providers[p.ID] = client
		}
		trust, e := host.ReadClientTrust()
		if e != nil {
			return e
		}
		expected, e := native.ExpectedReadiness(cfg, trust)
		if e != nil {
			return e
		}
		radius := &host.RadiusBackend{Local: cfg.Bootstrap.LocalAddress, Peer: cfg.Bootstrap.PeerAddress, Secret: bytes.TrimSpace(values[cfg.Bootstrap.HealthSecret.File]), Expected: expected}
		target := sources.FirewallTarget{Project: cfg.Network.Discovery.Firewall.Project, Node: cfg.Network.Discovery.Firewall.Node, Network: cfg.Network.Discovery.Firewall.Network}
		firewall, e := cloud.Firewall(target)
		if e != nil {
			return e
		}
		ops, e := sources.NewFileOperations(radius, firewall, target, protectedSecretValues(values))
		if e != nil {
			return e
		}
		ops.RetainedProofs = func(ctx context.Context) ([]string, error) {
			payloads, err := repository.UnresolvedSourcePayloads(ctx, target.Node)
			if err != nil {
				return nil, err
			}
			sourceConfig, err := SourceConfig(cfg)
			if err != nil {
				return nil, err
			}
			references := []string{}
			for _, payload := range payloads {
				var work struct {
					Node      string          `json:"node"`
					Candidate json.RawMessage `json:"candidate"`
				}
				if domain.DecodeJSONStrict(payload, &work) != nil || work.Node != target.Node {
					return nil, errors.New("unresolved source evidence malformed")
				}
				var candidates []domain.SourceCandidate
				if domain.DecodeJSONStrict(work.Candidate, &candidates) != nil {
					return nil, errors.New("unresolved source candidate malformed")
				}
				reference, err := sources.ExpectedProofGeneration(sourceConfig, candidates, time.Now())
				if err != nil {
					return nil, err
				}
				references = append(references, reference)
			}
			return references, nil
		}
		return applySources(ctx, o, func(context.Context, config.Config) (sources.Verifier, sources.Operations, error) {
			return verifier, ops, nil
		})
	})
}
