package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
)

func protectedAuthRecovery(ctx context.Context, cfg config.Config, o RunOptions) error {
	cfg, e := protectedConfiguration(cfg, o)
	if e != nil {
		return e
	}
	if e = cfg.Validate(); e != nil {
		return e
	}
	if o.AuthFilename == "" || o.AuthOffset < 0 || (!o.DryRun && len(o.AuthRangeSHA256) != 64) {
		return errors.New("exact native filename, offset, and original range digest required")
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
	record, e := host.InspectAuthQuarantine(ctx, backend, accounts, cfg.Hostname, o.AuthFilename, o.AuthOffset, o.AuthRangeSHA256, repository, !o.DryRun)
	if e != nil {
		return e
	}
	if o.DryRun {
		if o.Output == nil {
			return nil
		}
		return json.NewEncoder(o.Output).Encode(map[string]any{"dry_run": true, "source": record.Source, "offset": record.Start, "end": record.End, "sha256": record.SHA256})
	}
	_, hash, e := transitionBinding(cfg)
	if e != nil {
		return e
	}
	operation := "auth-quarantine:" + stateDigest([]byte(fmt.Sprintf("%s:%s:%s:%d:%d:%s", cfg.StateTransition, hash, record.Source, record.Start, record.End, record.SHA256)))
	if o.MaintenanceAttempt > 0 {
		return repository.ReconcileMaintenance(ctx, o.MaintenanceAttempt, func(ctx context.Context, original postgres.MaintenanceEvidence) error {
			if original.Operation != operation || original.Installation != "" {
				return errors.New("different original auth quarantine attempt")
			}
			proven, e := repository.AuthQuarantineRecorded(ctx, record)
			if e != nil || !proven {
				return errors.New("exact committed original malformed range not proven")
			}
			return nil
		})
	}
	return (postgres.MaintenanceGate{Store: repository}).With(ctx, operation, func(ctx context.Context) error {
		checked, e := host.InspectAuthQuarantine(ctx, backend, accounts, cfg.Hostname, o.AuthFilename, o.AuthOffset, record.SHA256, repository, true)
		if e != nil {
			return e
		}
		if checked.Inode != record.Inode || checked.Device != record.Device || checked.FileSize != record.FileSize {
			return errors.New("native auth evidence changed before protected recovery")
		}
		return repository.QuarantineAuth(ctx, checked)
	})
}
