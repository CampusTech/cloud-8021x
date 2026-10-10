package inventory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

type inventoryOnly struct {
	batch domain.DeviceSnapshot
	err   error
}

func (p inventoryOnly) Fetch(context.Context, domain.InventoryScope) (domain.DeviceSnapshot, error) {
	return p.batch, p.err
}

type withCertificates struct {
	inventoryOnly
	observation domain.CertificateObservation
}

func (p withCertificates) Collect(context.Context, domain.CertificateCollectionRequest) (domain.CertificateObservation, error) {
	return p.observation, nil
}
func TestSyncCapabilitySeparationAndAtomicPublication(t *testing.T) {
	fp := strings.Repeat("a", 64)
	fps := []string{fp}
	scope := domain.InventoryScope{ProviderID: "fake", IDs: []string{"one"}}
	batch := domain.DeviceSnapshot{Scope: scope, Complete: true, ObservedAt: 100, Devices: []domain.Device{{ID: "fake:one", Groups: []domain.GroupID{}, Identities: []string{"alias"}, Enrolled: true, Fingerprints: &fps, CertificatesObservedAt: 99}}}
	store := new(domain.SnapshotStore)
	path := filepath.Join(t.TempDir(), "inventory.json")
	service := Service{Provider: inventoryOnly{batch: batch}, Store: store, Path: path, Scope: scope}
	if err := service.Sync(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if store.View().ByCertificate(fp) != nil || store.View().SchemaVersion() != 1 {
		t.Fatal("inventory-only capability injected fingerprint")
	}
	service.Certificates = withCertificates{observation: domain.CertificateObservation{DeviceID: "fake:one", Fingerprints: fps, ObservedAt: 90.25, TrustVerified: true, Provenance: "authenticated:command"}}
	if err := service.Sync(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if got := store.View().ByCertificate(fp); got == nil || *got.ObservedAt != 90.25 {
		t.Fatal("original certificate observation lost")
	}
	before, _ := os.ReadFile(path)
	service.Provider = inventoryOnly{batch: domain.DeviceSnapshot{Scope: scope, Complete: false, ObservedAt: 200}}
	if err := service.Sync(context.Background(), false); !errors.Is(err, domain.ErrIncompleteSnapshot) {
		t.Fatalf("partial %v", err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) || store.View().Updated() != 100 {
		t.Fatal("partial publication")
	}
	service.Provider = inventoryOnly{batch: batch}
	service.Path = filepath.Join(t.TempDir(), "missing", "inventory.json")
	if err := service.Sync(context.Background(), false); err == nil {
		t.Fatal("failed file write accepted")
	}
	if store.View().Updated() != 100 {
		t.Fatal("file failure published store")
	}
}
func TestSyncRejectsUntrustedWrongDeviceAndScope(t *testing.T) {
	scope := domain.InventoryScope{ProviderID: "fake"}
	batch := domain.DeviceSnapshot{Scope: scope, Complete: true, ObservedAt: 100, Devices: []domain.Device{{ID: "fake:1", Groups: []domain.GroupID{}}}}
	for _, ob := range []domain.CertificateObservation{{DeviceID: "fake:1", TrustVerified: false}, {DeviceID: "fake:2", TrustVerified: true, Provenance: "command"}, {DeviceID: "fake:1", TrustVerified: true}} {
		s := Service{Provider: inventoryOnly{batch: batch}, Certificates: withCertificates{observation: ob}, Scope: scope, Store: new(domain.SnapshotStore), Path: filepath.Join(t.TempDir(), "i.json")}
		if err := s.Sync(context.Background(), false); err == nil {
			t.Fatal("unauthenticated certificate observation accepted")
		}
	}
	batch.Scope.IDs = []string{}
	s := Service{Provider: inventoryOnly{batch: batch}, Scope: scope, Store: new(domain.SnapshotStore), Path: filepath.Join(t.TempDir(), "i.json")}
	if err := s.Sync(context.Background(), false); err == nil {
		t.Fatal("nil/empty scope collapsed")
	}
}
