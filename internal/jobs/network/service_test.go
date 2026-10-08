package network

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	metadata "github.com/CampusTech/cloud-8021x/internal/network"
)

type inventoryOnly struct {
	batch domain.NetworkSnapshot
	err   error
}

func (f *inventoryOnly) Fetch(context.Context, domain.InventoryScope) (domain.NetworkSnapshot, error) {
	return f.batch, f.err
}
func TestInventoryOnlyScopeFailurePublicationAndDryRun(t *testing.T) {
	now := time.Now()
	scope := domain.InventoryScope{ProviderID: "fake", IDs: []string{"office", "home"}}
	f := &inventoryOnly{batch: domain.NetworkSnapshot{ProviderID: "fake", Scope: scope, Scopes: []domain.NetworkScopeResult{{ScopeID: "office", Status: domain.CapabilityAvailable, ObservedAt: domain.Unix(now)}, {ScopeID: "home", Status: domain.CapabilityUnsupported}}, VLANs: []domain.VLANMetadata{{SiteID: "office", ID: 10, Name: "Staff"}}}}
	r, e := metadata.NewRegistry([]metadata.Registration{{ID: "fake", Inventory: f, Scope: scope}})
	if e != nil {
		t.Fatal(e)
	}
	if r.Entries[0].Signaler != nil || r.Entries[0].Discovery != nil {
		t.Fatal("inventory-only capabilities fabricated")
	}
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "metadata")
	store := new(metadata.Store)
	s := Service{Registry: r, Store: store, Path: path, Key: "config-digest"}
	if e = s.Sync(context.Background(), true); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("dry run wrote metadata")
	}
	if e = s.Sync(context.Background(), false); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(path)
	var previous Document
	if e = json.Unmarshal(before, &previous); e != nil {
		t.Fatal(e)
	}
	f.err = errors.New("SENTINEL credential body")
	if e = s.Sync(context.Background(), false); e == nil {
		t.Fatal("failure hidden")
	}
	after, _ := os.ReadFile(path)
	var current Document
	if e = json.Unmarshal(after, &current); e != nil {
		t.Fatal(e)
	}
	if previous.Providers[0].Scopes[0].ObservedAt != current.Providers[0].Scopes[0].ObservedAt || store.Resolve("fake", "office", "", 10, now, time.Hour).VLAN != "Staff" {
		t.Fatal("failure replaced successful metadata")
	}
	s.Key = "different-controller"
	if e = s.Sync(context.Background(), false); e == nil {
		t.Fatal("expected refresh failure")
	}
	if store.Resolve("fake", "office", "", 10, now, time.Hour).VLAN != "" {
		t.Fatal("cross-controller stale cache reused")
	}
}
func TestScopeMismatchCannotPublish(t *testing.T) {
	now := time.Now()
	f := &inventoryOnly{batch: domain.NetworkSnapshot{ProviderID: "fake", Scope: domain.InventoryScope{ProviderID: "fake", IDs: []string{"foreign"}}, Scopes: []domain.NetworkScopeResult{{ScopeID: "foreign", Status: domain.CapabilityAvailable, ObservedAt: domain.Unix(now)}}}}
	r, _ := metadata.NewRegistry([]metadata.Registration{{ID: "fake", Inventory: f, Scope: domain.InventoryScope{ProviderID: "fake", IDs: []string{"pinned"}}}})
	if e := (&Service{Registry: r, Store: new(metadata.Store)}).Sync(context.Background(), false); e == nil {
		t.Fatal("foreign scope published")
	}
}
