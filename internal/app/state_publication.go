package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
)

type legacyPublicationStore interface {
	ImportLegacyBundle(context.Context, string, []byte) (bool, error)
	ConfirmLegacyPublication(context.Context, string, string, string) error
	EnableIfPublished(context.Context, string) (bool, error)
}

func stateDigest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func publishLegacyState(ctx context.Context, s legacyPublicationStore, id, node string, data []byte, resume bool, publish func() error) (bool, error) {
	if !resume {
		if _, e := s.ImportLegacyBundle(ctx, id, data); e != nil {
			return false, e
		}
	}
	if e := ctx.Err(); e != nil {
		return false, e
	}
	if e := publish(); e != nil {
		return false, e
	}
	if e := s.ConfirmLegacyPublication(ctx, id, node, stateDigest(data)); e != nil {
		return false, e
	}
	return s.EnableIfPublished(ctx, id)
}
func protectedStateMigrate(ctx context.Context, cfg config.Config, o RunOptions) error {
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
		return json.NewEncoder(o.Output).Encode(map[string]any{"dry_run": true, "operation": "state migrate", "transition": cfg.StateTransition, "node": node})
	}
	accounts, e := host.ReadAccounts()
	if e != nil {
		return e
	}
	values, e := host.CommittedCredentials(bootCredentialLayout(cfg, accounts))
	if e != nil {
		return e
	}
	data, e := host.ReadCapturedLegacyState(cfg.StateTransition, node, values[cfg.Policy.ClassSigningKey.File])
	if e != nil {
		return e
	}
	repository, e := postgres.NewMigration(ctx, string(values[cfg.Database.MigrationDSN.File]), cfg.Database)
	if e != nil {
		return e
	}
	defer repository.Close()
	unlock, e := host.AcquireWriterOperation()
	if e != nil {
		return e
	}
	defer unlock()
	if e = repository.RequireNodeWriterFences(ctx, cfg.StateTransition, node, hash); e != nil {
		return e
	}
	identity := postgres.StatePublicationIdentity{WriterFenceIdentity: postgres.WriterFenceIdentity{Transition: cfg.StateTransition, Node: node, ConfigSHA256: hash}, BundleSHA256: stateDigest(data)}
	physical := host.StatePublication{Transition: cfg.StateTransition, Node: node, ConfigSHA256: hash, BundleSHA256: identity.BundleSHA256, Attempt: o.MaintenanceAttempt}
	var enabled bool
	action := func(ctx context.Context) error {
		if o.MaintenanceAttempt == 0 {
			physical.Attempt, e = repository.StatePublicationAttempt(ctx, identity)
			if e != nil {
				return e
			}
			if e = host.PrepareStatePublication(physical, data); e != nil {
				return e
			}
		}
		var err error
		enabled, err = publishLegacyState(ctx, repository, cfg.StateTransition, node, data, o.MaintenanceAttempt > 0, func() error { return host.PublishCapturedState(physical, data) })
		return err
	}
	if o.MaintenanceAttempt > 0 {
		if e = host.ValidateStatePublicationRecovery(physical, data); e != nil {
			return e
		}
		e = repository.ResumeStatePublication(ctx, o.MaintenanceAttempt, identity, action)
	} else {
		operation, err := identity.Operation()
		if err != nil {
			return err
		}
		e = (postgres.MaintenanceGate{Store: repository}).With(ctx, operation, action)
	}
	if e != nil {
		return e
	}
	if o.Output == nil {
		return nil
	}
	return json.NewEncoder(o.Output).Encode(map[string]any{"operation": "state migrate", "node": node, "transition": cfg.StateTransition, "bundle_sha256": identity.BundleSHA256, "workers_enabled": enabled, "attempt": physical.Attempt})
}
