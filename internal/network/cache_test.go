package network

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

type fakeProvider struct {
	batch domain.NetworkSnapshot
	err   error
	calls int
}

func (f *fakeProvider) Fetch(context.Context, domain.InventoryScope) (domain.NetworkSnapshot, error) {
	f.calls++
	return f.batch, f.err
}
func privatePath(t *testing.T, name string) string {
	t.Helper()
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e == nil {
		e = os.Chmod(dir, 0700)
	}
	if e != nil {
		t.Fatal(e)
	}
	return filepath.Join(dir, name)
}
func TestCacheScopeIdentityExpiryAndPrivateFiles(t *testing.T) {
	now := time.Now()
	scope := domain.InventoryScope{ProviderID: "p", IDs: []string{"s"}}
	f := &fakeProvider{batch: domain.NetworkSnapshot{ProviderID: "p", Scope: scope, Scopes: []domain.NetworkScopeResult{{ScopeID: "s", Status: domain.CapabilityAvailable, ObservedAt: domain.Unix(now)}}}}
	path := privatePath(t, "cache")
	c := &CachedProvider{Provider: f, Key: "first-controller-credential-digest", Path: path, MaxAge: time.Minute, Now: func() time.Time { return now }}
	if _, e := c.Fetch(context.Background(), scope); e != nil {
		t.Fatal(e)
	}
	f.err = errors.New("offline")
	cached, e := c.Fetch(context.Background(), scope)
	if e != nil || f.calls != 1 || cached.Scopes[0].ObservedAt != domain.Unix(now) {
		t.Fatal("cache changed timestamp", e, f.calls)
	}
	c.Key = "other-controller"
	if _, e = c.Fetch(context.Background(), scope); e == nil {
		t.Fatal("accepted another controller cache")
	}
	c.Key = "first-controller-credential-digest"
	c.Now = func() time.Time { return now.Add(time.Hour) }
	if _, e = c.Fetch(context.Background(), scope); e == nil {
		t.Fatal("stale cache concealed failed fetch")
	}
	info, e := os.Stat(path)
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("cache is public")
	}
}
func TestPrivateFilesRejectLinksAndPublicMode(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "public", "ancestor"} {
		t.Run(kind, func(t *testing.T) {
			path := privatePath(t, "data")
			if e := os.WriteFile(path, []byte(`[]`), 0600); e != nil {
				t.Fatal(e)
			}
			bad := path
			switch kind {
			case "symlink":
				bad = filepath.Join(filepath.Dir(path), "link")
				if e := os.Symlink(path, bad); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				bad = filepath.Join(filepath.Dir(path), "link")
				if e := os.Link(path, bad); e != nil {
					t.Fatal(e)
				}
			case "public":
				if e := os.Chmod(path, 0644); e != nil {
					t.Fatal(e)
				}
			case "ancestor":
				alias := privatePath(t, "link")
				if e := os.Symlink(filepath.Dir(path), alias); e != nil {
					t.Fatal(e)
				}
				bad = filepath.Join(alias, "data")
			}
			if _, e := ReadPrivate(bad, os.Geteuid()); e == nil {
				t.Fatal("unsafe input read")
			}
			if e := WritePrivate(bad, []byte("changed")); e == nil {
				t.Fatal("unsafe output replaced")
			}
		})
	}
}
func TestMergePreservesFailedVLANOriginalTime(t *testing.T) {
	now := time.Now()
	scope := domain.InventoryScope{ProviderID: "p", IDs: []string{"s"}}
	old := domain.NetworkSnapshot{ProviderID: "p", Scope: scope, Scopes: []domain.NetworkScopeResult{{ScopeID: "s", Status: domain.CapabilityAvailable, ObservedAt: domain.Unix(now), VLANStatus: domain.CapabilityAvailable, VLANObservedAt: domain.Unix(now)}}, VLANs: []domain.VLANMetadata{{SiteID: "s", ID: 10, Name: "Staff"}}}
	next := domain.NetworkSnapshot{ProviderID: "p", Scope: scope, Scopes: []domain.NetworkScopeResult{{ScopeID: "s", Status: domain.CapabilityAvailable, ObservedAt: domain.Unix(now.Add(time.Minute)), VLANStatus: domain.CapabilityFailed}}}
	merged := Merge(old, next)
	if len(merged.VLANs) != 1 || merged.Scopes[0].VLANObservedAt != domain.Unix(now) {
		t.Fatal("merge freshened/lost labels", merged)
	}
}
