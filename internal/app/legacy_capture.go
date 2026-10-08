package app

import (
	"context"
	"errors"
	"os"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
)

// prepareLegacyCapture is the fixed pre-CA snapshot phase. It never operates a
// database/service and recovery only verifies the original durable evidence.
func prepareLegacyCapture(ctx context.Context, cfg config.Config, values map[string][]byte, store *postgres.Store, resume int64) error {
	node, hash, e := transitionBinding(cfg)
	if e != nil {
		return e
	}
	layout, e := currentWriterLayout()
	if e != nil {
		return e
	}
	writer, e := host.RevalidateLegacyWriterFence(ctx, cfg.StateTransition, node, layout)
	if e != nil {
		return e
	}
	operation := "legacy-capture:" + stateDigest([]byte(cfg.StateTransition+":"+node+":"+hash+":"+writer))
	class := values[cfg.Policy.ClassSigningKey.File]
	if e = host.CheckLegacyCaptureClass(class); e != nil {
		return e
	}
	if _, e = host.ReadLegacyPolicySnapshot(cfg.Policy.IdentityMode); e != nil {
		return e
	}
	// The read-only preflight catches an active old producer or unavailable local
	// SQL socket before opening a maintenance attempt. The gate repeats it.
	if e = host.PreflightLegacySQL(ctx, cfg.StateTransition, node, hash, writer); e != nil {
		return e
	}
	if resume > 0 {
		return store.ReconcileMaintenance(ctx, resume, func(ctx context.Context, m postgres.MaintenanceEvidence) error {
			if m.Operation != operation || m.Installation != "" {
				return errors.New("foreign legacy capture attempt")
			}
			if e := host.ProveLegacyCaptureStopped(cfg.StateTransition, node, hash, writer, resume); e != nil {
				return e
			}
			complete, e := host.LegacyCaptureRecorded(cfg.StateTransition, node, hash, writer, resume, class)
			if e != nil {
				return e
			}
			if !complete {
				installed, e := host.KnownInstallation()
				if e != nil || installed {
					return errors.New("legacy capture absent after installation")
				}
				return store.LegacyCaptureBeforeInstall(ctx, cfg.StateTransition, node, hash, writer)
			}
			return nil
		})
	}
	prior, e := host.LegacyCaptureOriginalAttempt(cfg.StateTransition, node, hash, writer)
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e == nil {
		complete, e := host.LegacyCaptureRecorded(cfg.StateTransition, node, hash, writer, prior, class)
		if e != nil {
			return e
		}
		if complete {
			return nil
		}
		if e = host.ProveLegacyCaptureStopped(cfg.StateTransition, node, hash, writer, prior); e != nil {
			return e
		}
	}
	return (postgres.MaintenanceGate{Store: store}).With(ctx, operation, func(ctx context.Context) error {
		if e := store.RequireNodeWriterFences(ctx, cfg.StateTransition, node, hash); e != nil {
			return e
		}
		if e := host.PreflightLegacySQL(ctx, cfg.StateTransition, node, hash, writer); e != nil {
			return e
		}
		attempt, e := store.LegacyCaptureAttempt(ctx, operation)
		if e != nil {
			return e
		}
		if e = host.PrepareLegacyCaptureAttempt(cfg.StateTransition, node, hash, writer, attempt); e != nil {
			return e
		}
		if e = host.CaptureLegacySQL(ctx, cfg.StateTransition, node, hash, writer); e != nil {
			return e
		}
		if _, e = host.CaptureLegacyState(cfg.StateTransition, node, class); e != nil {
			return e
		}
		return host.CompleteLegacyCapture(cfg.StateTransition, node, hash, writer, attempt, class)
	})
}
