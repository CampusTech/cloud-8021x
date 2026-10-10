package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
)

func TestInventoryRuntimeDryRunUsesOnlyObserverAndNoPublication(t *testing.T) {
	dir := t.TempDir()
	observer := filepath.Join(dir, "observer")
	if err := os.WriteFile(observer, []byte("observer"), 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer observer" {
			t.Error("dry-run collector side effect")
		}
		_, _ = w.Write([]byte(`{"hosts":[{"id":1,"uuid":"uuid","team_id":1,"mdm":{"enrollment_status":"On (automatic)"}}]}`))
	}))
	defer srv.Close()
	cfg := config.Defaults()
	cfg.Inventory.Enabled = true
	cfg.Inventory.Fleet.BaseURL = srv.URL
	cfg.Inventory.Fleet.ObserverToken = config.SecretRef{File: observer}
	cfg.Inventory.Fleet.ManagedCertificates = true
	cfg.Inventory.Fleet.MaintainerToken = config.SecretRef{File: filepath.Join(dir, "missing-maintainer")}
	cfg.Paths.InventoryFile = filepath.Join(dir, "inventory.json")
	cfg.Inventory.Fleet.CacheFile = filepath.Join(dir, "cache.json")
	service, closeService, err := InventoryServiceFromConfig(context.Background(), cfg, new(domain.SnapshotStore), true, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer closeService()
	if err = service.Sync(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("read-only dry run calls %d", calls)
	}
	for _, p := range []string{cfg.Paths.InventoryFile, cfg.Inventory.Fleet.CacheFile} {
		if _, err = os.Stat(p); !os.IsNotExist(err) {
			t.Fatal("dry-run published state", err)
		}
	}
	if err = os.Chmod(observer, 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err = InventoryServiceFromConfig(context.Background(), cfg, new(domain.SnapshotStore), true, srv.Client()); err == nil {
		t.Fatal("public observer credential accepted")
	}
}
