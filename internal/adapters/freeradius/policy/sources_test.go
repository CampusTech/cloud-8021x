package policy

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/privileged/sources"
)

func TestConfiguredPolicyPreservesStaticIPv6(t *testing.T) {
	data, e := os.ReadFile("../../../../examples/cloud-8021x.yaml")
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := config.Decode(bytes.NewReader(data))
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	s, r, h := setup(t)
	cfg.Paths.InventoryFile = filepath.Join(dir, "inventory")
	cfg.Paths.DowngradeGuardFile = filepath.Join(dir, "guard")
	cfg.Paths.HandoffDir = h.Directory
	cfg.Listeners.Policy.Token.File = filepath.Join(dir, "token")
	cfg.Policy.ClassSigningKey.File = filepath.Join(dir, "key")
	cfg.RadiusClients[0].ID = r.Server.ClientID
	cfg.RadiusClients[0].CIDRs = []string{"2001:db8::/64"}
	cfg.RadiusClients[1].CIDRs = []string{"198.51.100.1/32"}
	cfg.Policy.Rules[0].GroupID = "other:staff"
	if e = domain.PublishSnapshotFile(cfg.Paths.InventoryFile, s.Snapshots().Load()); e != nil {
		t.Fatal(e)
	}
	_ = os.WriteFile(cfg.Listeners.Policy.Token.File, bytes.Repeat([]byte("k"), 32), 0600)
	_ = os.WriteFile(cfg.Policy.ClassSigningKey.File, bytes.Repeat([]byte("A"), 64), 0600)
	local, _, e := FromConfig(cfg, nil)
	if e != nil {
		t.Fatal(e)
	}
	r.Server.SourceIP = "2001:db8::123"
	result, e := local.Decide(context.Background(), r)
	if e != nil || result.Decision.VLAN == nil {
		t.Fatal(result, e)
	}
}

func TestAppliedSourceResolverRetainsOriginalTTLAndStaticFallback(t *testing.T) {
	now := time.Now()
	cfg := sources.Config{MaxAge: time.Minute, Bindings: []sources.Binding{{ProviderID: "u", ProviderOrigin: "https://api.invalid", ConsoleID: "console", ClientID: "office", LocationID: "nyc", Medium: "wifi", SignalingProfile: "unifi-numeric", StaticCIDRs: []string{"192.0.2.0/24"}}}}
	trust, e := NewSourceTrust(cfg)
	if e != nil {
		t.Fatal(e)
	}
	trust.clock = func() time.Time { return now }
	state := sources.State{ConfigSHA256: cfg.Identity(), Candidates: []domain.SourceCandidate{{ProviderID: "u", SiteID: "console", ObservedAt: domain.Unix(now), CIDRs: []string{"8.8.8.8/32"}}}}
	trust.state.Store(&state)
	if _, e = trust.AuthenticatedClient("office", "8.8.8.8"); e != nil {
		t.Fatal(e)
	}
	now = now.Add(61 * time.Second)
	if _, e = trust.AuthenticatedClient("office", "8.8.8.8"); e == nil {
		t.Fatal("refreshed expired source")
	}
	if _, e = trust.AuthenticatedClient("office", "192.0.2.3"); e != nil {
		t.Fatal("static range coupled to discovery", e)
	}
	now = now.Add(-61 * time.Second)
	state.ConfigSHA256 = "different"
	trust.state.Store(&state)
	if _, e = trust.AuthenticatedClient("office", "8.8.8.8"); e == nil {
		t.Fatal("accepted different protected config")
	}
	if _, e = trust.AuthenticatedClient("attacker", "192.0.2.3"); e == nil {
		t.Fatal("packet selected location")
	}
}
