package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/CampusTech/cloud-8021x/internal/adapters/freeradius/native"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
)

func stateBackend(cfg config.Config, values map[string][]byte) (*host.RadiusBackend, error) {
	trust, e := host.ReadClientTrust()
	if e != nil {
		return nil, e
	}
	expected, e := native.ExpectedReadiness(cfg, trust)
	if e != nil {
		return nil, e
	}
	return &host.RadiusBackend{Local: cfg.Bootstrap.LocalAddress, Peer: cfg.Bootstrap.PeerAddress, Expected: expected, Secret: bytes.TrimSpace(values[cfg.Bootstrap.HealthSecret.File]), Companions: true}, nil
}
func protectedStateExport(ctx context.Context, cfg config.Config, o RunOptions) error {
	if o.MaintenanceAttempt > 0 && !o.FenceOnly {
		return errors.New("resume-attempt is export-fence-only")
	}
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
		return json.NewEncoder(o.Output).Encode(map[string]any{"dry_run": true, "operation": "state export", "fence_only": o.FenceOnly, "transition": cfg.StateTransition, "node": node, "native_stop_required": o.FenceOnly})
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
	backend, e := stateBackend(cfg, values)
	if e != nil {
		return e
	}
	unlock, e := host.AcquireWriterOperation()
	if e != nil {
		return e
	}
	defer unlock()
	if !o.FenceOnly {
		if e = repository.RequireWorkerExportReady(ctx, cfg.StateTransition); e != nil {
			return e
		}
		if _, e = host.VerifyDaemonWorkerFence(ctx, cfg.StateTransition, node, hash, backend); e != nil {
			return e
		}
		if _, e = host.CaptureDaemonState(cfg, accounts, values[cfg.Policy.ClassSigningKey.File]); e != nil {
			return e
		}
	} else if o.MaintenanceAttempt == 0 {
		if e = host.CheckRestart(ctx, backend); e != nil {
			return e
		}
	}
	gate := postgres.MaintenanceGate{Store: repository}
	identity := postgres.WorkerFenceIdentity{WriterFenceIdentity: postgres.WriterFenceIdentity{Transition: cfg.StateTransition, Node: node, ConfigSHA256: hash}}
	var output string
	if o.FenceOnly {
		fence := func(ctx context.Context) (string, []byte, error) {
			attempt, e := repository.WorkerFenceAttempt(ctx, identity)
			if e != nil {
				return "", nil, e
			}
			receipt, e := host.FenceDaemonWorkers(ctx, cfg.StateTransition, node, hash, backend, attempt, o.MaintenanceAttempt > 0)
			if e != nil {
				return "", nil, e
			}
			state, e := host.CaptureDaemonState(cfg, accounts, values[cfg.Policy.ClassSigningKey.File])
			return receipt, state, e
		}
		if o.MaintenanceAttempt > 0 {
			e = repository.ResumeWorkerFence(ctx, o.MaintenanceAttempt, identity, fence)
		} else {
			operation, err := identity.Operation()
			if err != nil {
				return err
			}
			e = gate.With(ctx, operation, func(ctx context.Context) error {
				if e := repository.BlockTransition(ctx, cfg.StateTransition); e != nil {
					return e
				}
				receipt, state, e := fence(ctx)
				if e != nil {
					return e
				}
				return repository.RecordWorkerState(ctx, cfg.StateTransition, receipt, state)
			})
		}
	} else {
		e = gate.With(ctx, "state-export:"+cfg.StateTransition, func(ctx context.Context) error {
			if _, e := host.VerifyDaemonWorkerFence(ctx, cfg.StateTransition, node, hash, backend); e != nil {
				return e
			}
			// Re-read the same local capture, including inode/hash/spool evidence. A
			// post-fence local mutation cannot hide behind the earlier SQL node receipt.
			if _, e := host.CaptureDaemonState(cfg, accounts, values[cfg.Policy.ClassSigningKey.File]); e != nil {
				return e
			}
			data, e := repository.ExportState(ctx, cfg.StateTransition)
			if e != nil {
				return e
			}
			output, e = host.WriteRollbackExport(cfg.StateTransition, data)
			return e
		})
	}
	if e != nil {
		return e
	}
	if o.Output == nil {
		return nil
	}
	return json.NewEncoder(o.Output).Encode(map[string]any{"operation": "state export", "node": node, "fence_only": o.FenceOnly, "transition": cfg.StateTransition, "path": output, "workers_blocked": true})
}
