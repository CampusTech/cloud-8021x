package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/fleet"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
)

// Initial inventory uses only the configured observer. There is no collector,
// repository/coordinator, result poller or source provider in this call graph.
func fetchFreshInventory(ctx context.Context, cfg config.Config, observer []byte, hc *http.Client) ([]byte, error) {
	if !cfg.Inventory.Enabled || cfg.Inventory.Provider != "fleet" || cfg.Policy.IdentityMode != "fingerprint" {
		return nil, errors.New("fresh fingerprint inventory requires configured observer")
	}
	client, e := fleet.NewClient(cfg.Inventory.Fleet.BaseURL, string(bytes.TrimSpace(observer)), hc, cfg.Inventory.Fleet.Timeout)
	if e != nil {
		return nil, e
	}
	provider := &fleet.Observer{Client: client, HostIDs: cfg.Inventory.Fleet.HostIDs, TeamIDs: cfg.Inventory.Fleet.TeamIDs, AllowLabel: cfg.Inventory.Fleet.AllowLabel}
	batch, e := provider.Fetch(ctx, domain.InventoryScope{ProviderID: "fleet", IDs: cfg.Inventory.Fleet.HostIDs})
	if e != nil {
		return nil, e
	}
	if !batch.Complete || batch.ObservedAt <= 0 || batch.ObservedAt > domain.Unix(time.Now()) || len(batch.Devices) == 0 {
		return nil, errors.New("fresh observer inventory unavailable or empty")
	}
	for i := range batch.Devices {
		batch.Devices[i].Fingerprints = nil
		batch.Devices[i].CertificatesObservedAt = 0
		batch.Devices[i].HardwareSerial = ""
	}
	snapshot, e := domain.BuildSnapshot(batch.Devices, batch.ObservedAt)
	if e != nil {
		return nil, e
	}
	snapshot.Version = 2
	snapshot.Certificates = map[string]*domain.DeviceRecord{}
	snapshot.HardwareSerials = map[string]*domain.DeviceRecord{}
	return json.Marshal(snapshot)
}
func prepareFreshInventory(ctx context.Context, cfg config.Config, values map[string][]byte, store *postgres.Store, bundle []byte, resume int64) ([]byte, error) {
	node, hash, e := transitionBinding(cfg)
	if e != nil {
		return nil, e
	}
	digest := stateDigest(bundle)
	original, e := host.VerifyFreshState(cfg.StateTransition, node, hash, values[cfg.Policy.ClassSigningKey.File])
	if e != nil || !bytes.Equal(original, bundle) {
		return nil, errors.New("fresh original physical proof differs")
	}
	operation := "fresh-initial:" + stateDigest([]byte(cfg.StateTransition+":"+node+":"+hash+":"+digest))
	snapshot, e := host.ReadFreshInventory(cfg.StateTransition, node, hash, digest)
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	if resume > 0 {
		if e != nil {
			return nil, e
		}
		e = store.ReconcileMaintenance(ctx, resume, func(ctx context.Context, m postgres.MaintenanceEvidence) error {
			if m.Operation != operation || m.Installation != "" {
				return errors.New("foreign fresh preparation attempt")
			}
			if e := host.ProveFreshInventoryStopped(cfg.StateTransition, node, hash, digest, resume); e != nil {
				return e
			}
			committed, e := store.FreshInitialRecorded(ctx, cfg.StateTransition, node, hash, digest, snapshot)
			if e != nil {
				return e
			}
			if !committed {
				// Positive original absence must still hold. This reads only the already
				// captured original bundle and rejects installation/data footprints.
				original, e := host.VerifyFreshState(cfg.StateTransition, node, hash, values[cfg.Policy.ClassSigningKey.File])
				if e != nil || !bytes.Equal(original, bundle) {
					return errors.New("fresh no-commit physical proof differs")
				}
			}
			return nil
		})
		return nil, e
	}
	if e == nil {
		committed, e := store.FreshInitialRecorded(ctx, cfg.StateTransition, node, hash, digest, snapshot)
		if e != nil {
			return nil, e
		}
		if committed {
			return snapshot, nil
		}
	} else {
		snapshot, e = fetchFreshInventory(ctx, cfg, values[cfg.Inventory.Fleet.ObserverToken.File], nil)
		if e != nil {
			return nil, e
		}
	}
	e = (postgres.MaintenanceGate{Store: store}).With(ctx, operation, func(ctx context.Context) error {
		if e := store.RequireFreshEmpty(ctx, cfg.StateTransition); e != nil {
			return e
		}
		if e := store.RequireNodeWriterFences(ctx, cfg.StateTransition, node, hash); e != nil {
			return e
		}
		original, e := host.VerifyFreshState(cfg.StateTransition, node, hash, values[cfg.Policy.ClassSigningKey.File])
		if e != nil || !bytes.Equal(original, bundle) {
			return errors.New("fresh original changed before preparation")
		}
		attempt, e := store.FreshInitialAttempt(ctx, operation)
		if e != nil {
			return e
		}
		if e = host.PrepareFreshInventory(cfg.StateTransition, node, hash, digest, snapshot, attempt); e != nil {
			return e
		}
		if e = store.RecordFreshInventory(ctx, cfg.StateTransition, node, hash, digest, snapshot); e != nil {
			return e
		}
		committed, e := store.FreshInitialRecorded(ctx, cfg.StateTransition, node, hash, digest, snapshot)
		if e != nil {
			return e
		}
		if !committed {
			return errors.New("fresh initial commit unknown")
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	return snapshot, nil
}
