package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/adapters/fleet"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
)

type transitionPreparation interface {
	RecordWriterFence(context.Context, string, string, string, string) error
	RequireNodeWriterFences(context.Context, string, string, string) error
}

func transitionBinding(cfg config.Config) (string, string, error) {
	if len(cfg.StateTransition) != 64 || (cfg.InstanceID != "radius-primary" && cfg.InstanceID != "radius-secondary") {
		return "", "", errors.New("protected transition and fixed radius-primary/radius-secondary instance required")
	}
	if _, e := hex.DecodeString(cfg.StateTransition); e != nil {
		return "", "", errors.New("invalid transition")
	}
	data, e := json.Marshal(cfg)
	if e != nil {
		return "", "", e
	}
	sum := sha256.Sum256(data)
	return cfg.InstanceID, hex.EncodeToString(sum[:]), nil
}

// The incoming preparation uses validated in-memory credentials and cannot
// depend on a completed installation/credential cache that does not exist yet.
func bootstrapTransition(ctx context.Context, cfg config.Config, o RunOptions, store transitionPreparation, gate func(context.Context, string, func(context.Context) error) error, fence func(context.Context, string, string, string) (string, error)) error {
	node, hash, e := transitionBinding(cfg)
	if e != nil {
		return e
	}
	if !o.FenceOnly {
		return store.RequireNodeWriterFences(ctx, cfg.StateTransition, node, hash)
	}
	if !o.Incoming {
		return errors.New("fence-only requires the fixed incoming bootstrap selector")
	}
	operation, e := (postgres.WriterFenceIdentity{Transition: cfg.StateTransition, Node: node, ConfigSHA256: hash}).Operation()
	if e != nil {
		return e
	}
	e = gate(ctx, operation, func(ctx context.Context) error {
		receipt, e := fence(ctx, cfg.StateTransition, node, hash)
		if e != nil {
			return e
		}
		return store.RecordWriterFence(ctx, cfg.StateTransition, node, hash, receipt)
	})
	if e != nil {
		return e
	}
	if o.Output == nil {
		return nil
	}
	return json.NewEncoder(o.Output).Encode(struct{ Status, Transition, Node string }{"prepared; waiting for both nodes and full state import", cfg.StateTransition, node})
}
func protectedStateFence(ctx context.Context, cfg config.Config, o RunOptions) error {
	cfg, e := protectedConfiguration(cfg, o)
	if e != nil {
		return e
	}
	if e = cfg.Validate(); e != nil {
		return e
	}
	node, hash, e := transitionBinding(cfg)
	if e != nil {
		return e
	}
	if o.DryRun {
		if o.Output == nil {
			return nil
		}
		return json.NewEncoder(o.Output).Encode(map[string]any{"dry_run": true, "operation": "state fence", "node": node, "transition": cfg.StateTransition})
	}
	accounts, e := host.ReadAccounts()
	if e != nil {
		return e
	}
	values, e := host.CommittedCredentials(bootCredentialLayout(cfg, accounts))
	if e != nil {
		return e
	}
	repository, e := postgres.NewMigration(ctx, string(values[cfg.Database.MigrationDSN.File]), cfg.Database)
	if e != nil {
		return e
	}
	defer repository.Close()
	gate := postgres.MaintenanceGate{Store: repository}
	unlock, e := host.AcquireWriterOperation()
	if e != nil {
		return e
	}
	defer unlock()
	identity := postgres.WriterFenceIdentity{Transition: cfg.StateTransition, Node: node, ConfigSHA256: hash}
	if o.MaintenanceAttempt > 0 {
		return repository.ResumeWriterFence(ctx, o.MaintenanceAttempt, identity, func(ctx context.Context) (string, error) {
			receipt, e := host.RecoverLegacyWriterFence(ctx, cfg.StateTransition, node, hash)
			if e != nil {
				return "", e
			}
			if fresh, e := host.HasFreshPreparation(cfg.StateTransition); e != nil {
				return "", e
			} else if fresh {
				raw, e := host.CaptureFreshState(cfg.StateTransition, node, hash, values[cfg.Policy.ClassSigningKey.File])
				if e != nil {
					return "", e
				}
				if e = repository.RecordFreshSeed(ctx, cfg.StateTransition, hash, raw); e != nil {
					return "", e
				}
			}
			return receipt, nil
		})
	}
	operation, e := identity.Operation()
	if e != nil {
		return e
	}
	e = gate.With(ctx, operation, func(ctx context.Context) error {
		receipt, e := preparedWriterFence(ctx, cfg, values, repository)
		if e != nil {
			return e
		}
		return repository.RecordWriterFence(ctx, cfg.StateTransition, node, hash, receipt)
	})
	if e != nil {
		return e
	}
	if o.Output == nil {
		return nil
	}
	return json.NewEncoder(o.Output).Encode(map[string]string{"status": "local writers fenced", "transition": cfg.StateTransition, "node": node})
}

// One-shot refreshes obey the same shared migration gate as scheduled refreshes.
// Protected rollback also proves every worker process quiescent before export.
func requireRuntimeTransition(ctx context.Context, cfg config.Config) error {
	dsn, e := readInventoryFile(cfg.Database.RuntimeDSN.File, true, 64<<10)
	if e != nil {
		return e
	}
	s, e := postgres.NewRuntime(ctx, strings.TrimSpace(string(dsn)), cfg.Database, config.PoolObservation)
	if e != nil {
		return e
	}
	defer s.Close()
	return s.WorkersAllowed(ctx, cfg.StateTransition)
}

// All callers run inside root maintenance. First adoption has no completed cache;
// upgrades must prove the exact completed old bytes before adding a new binding.
func preparedWriterFence(ctx context.Context, cfg config.Config, values map[string][]byte, repository *postgres.Store) (string, error) {
	node, next, e := transitionBinding(cfg)
	if e != nil {
		return "", e
	}
	known, e := host.KnownInstallation()
	if e != nil {
		return "", e
	}
	if !known {
		fresh, e := host.PrepareFreshState(cfg.StateTransition, node, next, values[cfg.Policy.ClassSigningKey.File])
		if e != nil {
			return "", e
		}
		if fresh {
			if e = repository.RequireFreshEmpty(ctx, cfg.StateTransition); e != nil {
				return "", e
			}
		}
		receipt, e := host.FenceLegacyWriters(ctx, cfg.StateTransition, node, next)
		if e != nil {
			return "", e
		}
		if fresh {
			raw, e := host.CaptureFreshState(cfg.StateTransition, node, next, values[cfg.Policy.ClassSigningKey.File])
			if e != nil {
				return "", e
			}
			if e = repository.RecordFreshSeed(ctx, cfg.StateTransition, next, raw); e != nil {
				return "", e
			}
		}
		return receipt, nil
	}
	old, e := readProtectedSourceConfig()
	if e != nil {
		return "", e
	}
	if e = host.ValidateWriterUpgrade(old, cfg); e != nil {
		return "", e
	}
	accounts, e := host.ReadAccounts()
	if e != nil {
		return "", e
	}
	layout := bootCredentialLayout(old, accounts)
	committed, e := host.CommittedCredentials(layout)
	if e != nil {
		return "", e
	}
	if !bytes.Equal(committed[old.Database.MigrationDSN.File], values[cfg.Database.MigrationDSN.File]) {
		return "", errors.New("writer upgrade database credentials differ; coordinated transfer required")
	}
	_, prior, e := transitionBinding(old)
	if e != nil {
		return "", e
	}
	receipt, e := host.RevalidateLegacyWriterFence(ctx, cfg.StateTransition, node, layout)
	if e != nil {
		return "", e
	}
	if prior == next {
		return receipt, nil
	}
	if e = host.AppendWriterBinding(cfg.StateTransition, node, prior, next, receipt); e != nil {
		return "", e
	}
	if e = repository.RebindWriterFence(ctx, cfg.StateTransition, node, prior, next, receipt); e != nil {
		return "", e
	}
	return receipt, nil
}
func currentWriterLayout() ([]host.File, error) {
	known, e := host.KnownInstallation()
	if e != nil || !known {
		return nil, e
	}
	old, e := readProtectedSourceConfig()
	if e != nil {
		return nil, e
	}
	accounts, e := host.ReadAccounts()
	if e != nil {
		return nil, e
	}
	return bootCredentialLayout(old, accounts), nil
}

// The protected selector and committed credential cache supply the endpoint and
// scoped Fleet credential for read-only result recovery. The caller supplies only the original guard ID.
func protectedLegacyRecovery(ctx context.Context, cfg config.Config, o RunOptions) error {
	cfg, e := protectedConfiguration(cfg, o)
	if e != nil {
		return e
	}
	if e = cfg.Validate(); e != nil {
		return e
	}
	if len(o.LegacyGuardID) != 64 {
		return errors.New("exact legacy guard digest required")
	}
	if _, e = hex.DecodeString(o.LegacyGuardID); e != nil {
		return e
	}
	if !cfg.Inventory.Enabled || cfg.Inventory.Provider != "fleet" {
		return errors.New("configured Fleet inventory required")
	}
	if o.DryRun {
		if o.Output == nil {
			return nil
		}
		return json.NewEncoder(o.Output).Encode(map[string]any{"dry_run": true, "operation": "state recover-collection", "guard": o.LegacyGuardID})
	}
	accounts, e := host.ReadAccounts()
	if e != nil {
		return e
	}
	values, e := host.CommittedCredentials(bootCredentialLayout(cfg, accounts))
	if e != nil {
		return e
	}
	repository, e := postgres.NewMigration(ctx, string(values[cfg.Database.MigrationDSN.File]), cfg.Database)
	if e != nil {
		return e
	}
	defer repository.Close()
	client, e := fleet.NewClient(cfg.Inventory.Fleet.BaseURL, string(bytes.TrimSpace(values[cfg.Inventory.Fleet.MaintainerToken.File])), nil, cfg.Inventory.Fleet.Timeout)
	if e != nil {
		return e
	}
	unlock, e := host.AcquireWriterOperation()
	if e != nil {
		return e
	}
	defer unlock()
	node, hash, e := transitionBinding(cfg)
	if e != nil {
		return e
	}
	operation := "legacy-collection:" + stateDigest([]byte(cfg.StateTransition+":"+node+":"+hash+":"+o.LegacyGuardID+":"+o.LegacyExecutionID))
	if o.MaintenanceAttempt > 0 {
		return repository.ReconcileMaintenance(ctx, o.MaintenanceAttempt, func(ctx context.Context, original postgres.MaintenanceEvidence) error {
			if original.Operation != operation || original.Installation != "" {
				return errors.New("different original legacy resolution attempt")
			}
			return repository.LegacyCollectionResolved(ctx, o.LegacyGuardID)
		})
	}
	return resolveLegacyGuard(ctx, repository, client, postgres.MaintenanceGate{Store: repository}, o.LegacyGuardID, operation, o.LegacyExecutionID)
}
