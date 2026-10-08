package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os/user"
	"strconv"
	"time"

	networkjob "github.com/CampusTech/cloud-8021x/internal/jobs/network"

	"fmt"
	"path/filepath"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/adapters/freeradius/native"
	"github.com/CampusTech/cloud-8021x/internal/adapters/gcp"
	"github.com/CampusTech/cloud-8021x/internal/adapters/unifi"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/jobs"
	"github.com/CampusTech/cloud-8021x/internal/network"
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
	if o.SourceWorkID != "" {
		return recoverSourceAttempt(ctx, cfg, o, values, cloud, repository)
	}
	owner, e := user.Lookup(cfg.RuntimeUser)
	if e != nil {
		return errors.New("source producer unavailable")
	}
	uid, e := strconv.Atoi(owner.Uid)
	if e != nil || uid <= 0 {
		return errors.New("invalid source producer")
	}
	candidates, e := sources.ReadCandidate(cfg.Network.Discovery.CandidateFile, uid)
	if e != nil {
		return e
	}
	if e = checkSourceDigest(candidates, o.SourceCandidateSHA256); e != nil {
		return e
	}
	return coordinateSourceAttempt(ctx, repository.ForTransition(cfg.StateTransition), cfg.Network.Discovery.Firewall.Node, cfg.InstanceID+"-root", candidates, func(ctx context.Context, claimed []domain.SourceCandidate, digest string, claim jobs.Claim) error {
		o.SourceCandidateSHA256 = digest
		gate := postgres.MaintenanceGate{Store: repository}
		operation, e := sourceMaintenanceIdentity(cfg, claim.ID, claim.Generation, claim.Payload)
		if e != nil {
			return e
		}
		return gate.With(ctx, operation, func(ctx context.Context) error {
			verifier, ops, e := protectedSourceOperations(ctx, cfg, values, cloud, repository)
			if e != nil {
				return e
			}

			return applySourceCandidate(ctx, cfg, o, claimed, verifier, ops)
		})
	})
}

func coordinateSources(ctx context.Context, coordinator networkjob.SourceCoordinator, node, owner string, candidates []domain.SourceCandidate, apply func(context.Context, []domain.SourceCandidate, string) error) error {
	return coordinateSourceAttempt(ctx, coordinator, node, owner, candidates, func(ctx context.Context, c []domain.SourceCandidate, d string, _ jobs.Claim) error {
		return apply(ctx, c, d)
	})
}
func coordinateSourceAttempt(ctx context.Context, coordinator networkjob.SourceCoordinator, node, owner string, candidates []domain.SourceCandidate, apply func(context.Context, []domain.SourceCandidate, string, jobs.Claim) error) error {
	payload, err := json.Marshal(candidates)
	if err != nil {
		return err
	}
	job := networkjob.ApplyJob{Coordinator: coordinator, Node: node, Owner: owner, ApplyClaim: func(ctx context.Context, claim jobs.Claim, persisted json.RawMessage) error {
		var claimed []domain.SourceCandidate
		if domain.DecodeJSONStrict(persisted, &claimed) != nil {
			return errors.New("invalid claimed candidate")
		}
		digest := sha256.Sum256(persisted)
		return apply(ctx, claimed, hex.EncodeToString(digest[:]), claim)
	}}
	return job.Run(ctx, payload)
}

func protectedSourceOperations(ctx context.Context, cfg config.Config, values map[string][]byte, cloud *gcp.Client, repository *postgres.Store) (RootVerifier, *sources.FileOperations, error) {
	verifier := RootVerifier{Providers: map[string]domain.SourceDiscoveryProvider{}}
	for _, p := range cfg.Network.Providers {
		if p.Kind != "unifi" || p.ConsoleID == "" {
			continue
		}
		client, e := unifi.New(p.ID, p.BaseURL, string(bytes.TrimSpace(values[p.Credential.File])), nil, p.Timeout, nil)
		if e != nil {
			return RootVerifier{}, nil, e
		}
		client.ConsoleID = p.ConsoleID
		verifier.Providers[p.ID] = client
	}
	trust, e := host.ReadClientTrust()
	if e != nil {
		return RootVerifier{}, nil, e
	}
	expected, e := native.ExpectedReadiness(cfg, trust)
	if e != nil {
		return RootVerifier{}, nil, e
	}
	radius := &host.RadiusBackend{Local: cfg.Bootstrap.LocalAddress, Peer: cfg.Bootstrap.PeerAddress, Secret: bytes.TrimSpace(values[cfg.Bootstrap.HealthSecret.File]), Expected: expected}
	target := sources.FirewallTarget{Project: cfg.Network.Discovery.Firewall.Project, Node: cfg.Network.Discovery.Firewall.Node, Network: cfg.Network.Discovery.Firewall.Network}
	firewall, e := cloud.Firewall(target)
	if e != nil {
		return RootVerifier{}, nil, e
	}
	ops, e := sources.NewFileOperations(radius, firewall, target, protectedSecretValues(values))
	if e != nil {
		return RootVerifier{}, nil, e
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
	return verifier, ops, nil
}

func sourceMaintenanceIdentity(cfg config.Config, id string, generation int64, payload json.RawMessage) (string, error) {
	if generation < 1 || !strings.HasPrefix(id, "sources:") || len(id) != 72 {
		return "", errors.New("invalid source attempt")
	}
	var work struct {
		Node      string          `json:"node"`
		Candidate json.RawMessage `json:"candidate"`
	}
	if domain.DecodeJSONStrict(payload, &work) != nil || work.Node != cfg.Network.Discovery.Firewall.Node || work.Node != cfg.InstanceID {
		return "", errors.New("source attempt node mismatch")
	}
	_, hash, e := transitionBinding(cfg)
	if e != nil {
		return "", e
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d:%s", hash, id, generation, payload)))
	return "sources-apply:" + hex.EncodeToString(sum[:]), nil
}
func recoverSourceAttempt(ctx context.Context, cfg config.Config, o RunOptions, values map[string][]byte, cloud *gcp.Client, repository *postgres.Store) error {
	work, e := repository.LookupWork(ctx, o.SourceWorkID)
	if e != nil {
		return e
	}
	if work.State != "quarantine" || work.Generation != o.SourceGeneration {
		return errors.New("exact quarantined source generation required")
	}
	operation, e := sourceMaintenanceIdentity(cfg, o.SourceWorkID, o.SourceGeneration, work.Payload)
	if e != nil {
		return e
	}
	_, ops, e := protectedSourceOperations(ctx, cfg, values, cloud, repository)
	if e != nil {
		return e
	}
	sc, e := SourceConfig(cfg)
	if e != nil {
		return e
	}
	verify := func(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
		if !bytes.Equal(payload, work.Payload) {
			return nil, errors.New("source recovery payload changed")
		}
		var w struct {
			Node      string          `json:"node"`
			Candidate json.RawMessage `json:"candidate"`
		}
		if domain.DecodeJSONStrict(payload, &w) != nil {
			return nil, errors.New("source recovery payload invalid")
		}
		var c []domain.SourceCandidate
		if domain.DecodeJSONStrict(w.Candidate, &c) != nil {
			return nil, errors.New("source recovery candidate invalid")
		}
		evidence, e := (&sources.Applier{Config: sc, Operations: ops}).ReconcileHistoricalApplied(ctx, c)
		if e != nil {
			return nil, e
		}
		return json.Marshal(evidence)
	}
	return network.WithPrivateLock(ctx, filepath.Join(filepath.Dir(sources.ClientsFile), "apply.lock"), func() error {
		if o.MaintenanceAttempt > 0 {
			if e := repository.ReconcileMaintenance(ctx, o.MaintenanceAttempt, func(ctx context.Context, m postgres.MaintenanceEvidence) error {
				if m.Operation != operation || m.Installation != "" {
					return errors.New("foreign source maintenance attempt")
				}
				_, e := verify(ctx, work.Payload)
				return e
			}); e != nil {
				return e
			}
		}
		gate := postgres.MaintenanceGate{Store: repository}
		return gate.With(ctx, "source-history:"+strings.TrimPrefix(operation, "sources-apply:"), func(ctx context.Context) error {
			return repository.ReconcileHistoricalSource(ctx, cfg.StateTransition, cfg.InstanceID, o.SourceWorkID, o.SourceGeneration, verify)
		})
	})
}
