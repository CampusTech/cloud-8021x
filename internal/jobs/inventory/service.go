// Package inventory refreshes local authorization generations without vendor dependencies.
package inventory

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/inventory"
	"github.com/sirupsen/logrus"
)

type Service struct {
	Provider     domain.DeviceInventoryProvider
	Certificates domain.ManagedCertificateProvider
	Scope        domain.InventoryScope
	Store        *domain.SnapshotStore
	Path         string
	Logger       *logrus.Logger
	mu           sync.Mutex
}

// Sync is shared by the scheduled job and inventory sync command. DryRun performs
// inventory reads only, with no certificate submission, durable reservation or publication.
func (s *Service) Sync(ctx context.Context, dryRun bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Provider == nil || s.Store == nil || s.Path == "" {
		return errors.New("inventory service requires provider, store and destination")
	}
	batch, err := s.Provider.Fetch(ctx, s.Scope)
	if err != nil {
		return err
	}
	if !batch.Complete {
		return domain.ErrIncompleteSnapshot
	}
	if !reflect.DeepEqual(batch.Scope, s.Scope) {
		return errors.New("inventory provider returned different scope")
	}
	if s.Certificates != nil && !dryRun {
		if preparer, ok := s.Certificates.(interface {
			Prepare(context.Context, domain.DeviceSnapshot) error
		}); ok {
			if err = preparer.Prepare(ctx, batch); err != nil {
				return err
			}
		}
	}
	for i := range batch.Devices {
		d := &batch.Devices[i]
		d.Fingerprints = nil
		d.CertificatesObservedAt = 0
		if s.Certificates == nil || dryRun {
			continue
		}
		empty := []string{}
		d.Fingerprints = &empty
		ob, err := s.Certificates.Collect(ctx, domain.CertificateCollectionRequest{DeviceID: d.ID})
		if errors.Is(err, inventory.ErrPending) || errors.Is(err, inventory.ErrIneligible) {
			continue
		}
		if err != nil {
			return err
		}
		if ob.DeviceID != d.ID || !ob.TrustVerified || ob.Provenance == "" || ob.ObservedAt <= 0 || ob.ObservedAt > domain.Unix(time.Now()) {
			return errors.New("certificate observation lacks authenticated provenance")
		}
		d.Fingerprints = &ob.Fingerprints
		d.CertificatesObservedAt = ob.ObservedAt
	}
	snapshot, err := domain.BuildSnapshot(batch.Devices, batch.ObservedAt)
	if err != nil {
		return err
	}
	// Validate before changing either destination. Set below is then infallible for
	// this validated generation; a failed file write never updates memory.
	var validated domain.SnapshotStore
	if err = validated.Set(snapshot); err != nil {
		return err
	}
	snapshot = validated.Load()
	if err = ctx.Err(); err != nil {
		return err
	}
	if dryRun {
		return nil
	}
	if err = domain.PublishSnapshotFile(s.Path, snapshot); err != nil {
		return fmt.Errorf("inventory snapshot publication failed: %w", err)
	}
	if err = s.Store.Set(snapshot); err != nil {
		return err
	}
	if s.Logger != nil {
		s.Logger.WithFields(logrus.Fields{"provider": s.Scope.ProviderID, "devices": len(batch.Devices), "observed_at": batch.ObservedAt}).Debug("inventory generation published")
	}
	return nil
}
