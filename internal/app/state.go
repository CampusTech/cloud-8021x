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

func stateDigest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
