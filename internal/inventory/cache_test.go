package inventory

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

type countedProvider struct {
	calls int
	err   error
}

func (p *countedProvider) Fetch(_ context.Context, s domain.InventoryScope) (domain.DeviceSnapshot, error) {
	p.calls++
	return domain.DeviceSnapshot{Scope: s, Complete: true, ObservedAt: 100.125, Devices: []domain.Device{{ID: "fake:1", Groups: []domain.GroupID{}}}}, p.err
}
func TestDevelopmentCacheRetainsObservationAndScope(t *testing.T) {
	p := new(countedProvider)
	now := time.Unix(110, 0)
	scope := domain.InventoryScope{ProviderID: "fake"}
	cache := CachedProvider{Provider: p, Path: filepath.Join(t.TempDir(), "cache.json"), MaxAge: time.Minute, Now: func() time.Time { return now }}
	for range 2 {
		b, err := cache.Fetch(context.Background(), scope)
		if err != nil || b.ObservedAt != 100.125 {
			t.Fatalf("cache freshened provenance %+v %v", b, err)
		}
	}
	if p.calls != 1 {
		t.Fatalf("response cache missed %d", p.calls)
	}
	now = time.Unix(170, 0)
	p.err = errors.New("offline")
	if _, err := cache.Fetch(context.Background(), scope); err == nil {
		t.Fatal("stale cache freshened failed refresh")
	}
	p.err = nil
	scope.IDs = []string{}
	if _, err := cache.Fetch(context.Background(), scope); err != nil {
		t.Fatal(err)
	}
	if p.calls != 3 {
		t.Fatal("scope mismatch reused cache")
	}
}

func TestDevelopmentCacheCannotCrossSourceOrFilterConfiguration(t *testing.T) {
	provider := new(countedProvider)
	now := time.Unix(110, 0)
	scope := domain.InventoryScope{ProviderID: "fleet"}
	cache := CachedProvider{Provider: provider, Key: "source-and-team-a", Path: filepath.Join(t.TempDir(), "cache.json"), MaxAge: time.Minute, Now: func() time.Time { return now }}
	if _, err := cache.Fetch(context.Background(), scope); err != nil {
		t.Fatal(err)
	}
	cache.Key = "source-and-team-b"
	if _, err := cache.Fetch(context.Background(), scope); err != nil {
		t.Fatal(err)
	}
	if provider.calls != 2 {
		t.Fatal("source/filter configuration reused broader earlier response")
	}
}
