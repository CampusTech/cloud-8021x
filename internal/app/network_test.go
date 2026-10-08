package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/network"
	"github.com/CampusTech/cloud-8021x/internal/privileged/sources"
)

func TestNetworkFactoryDryRunCapabilitiesAndFreshRootDiscovery(t *testing.T) {
	dir := t.TempDir()
	credential := filepath.Join(dir, "key")
	if e := os.WriteFile(credential, []byte("synthetic"), 0600); e != nil {
		t.Fatal(e)
	}
	wanCalls := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "synthetic" {
			t.Error("missing key")
		}
		if r.URL.Path == "/v1/hosts" {
			wanCalls++
			_, _ = w.Write([]byte(`{"data":[{"id":"console","ipAddress":"8.8.8.8"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[],"offset":0,"count":0,"totalCount":0}`))
	}))
	defer s.Close()
	cfg := config.Defaults()
	cfg.Network.Providers = []config.NetworkProvider{{ID: "u", Kind: "unifi", ConsoleID: "console", BaseURL: s.URL + "/v1", Scopes: []string{"office"}, Credential: config.SecretRef{File: credential}, CacheFile: filepath.Join(dir, "cache")}}
	cfg.Network.Discovery.Bindings = []config.SourceBinding{{ProviderID: "u", ClientID: "client"}}
	cfg.Paths.MetadataFile = filepath.Join(dir, "metadata")
	service, e := NetworkServiceFromConfig(cfg, new(network.Store), true, s.Client())
	if e != nil {
		t.Fatal(e)
	}
	if e = service.Sync(context.Background(), true); e == nil {
		t.Fatal("missing pinned site must fail")
	}
	for _, p := range []string{cfg.Paths.MetadataFile, cfg.Network.Providers[0].CacheFile} {
		if _, e = os.Stat(p); !os.IsNotExist(e) {
			t.Fatal("dry-run wrote state")
		}
	}
	r := service.Registry.Entries[0]
	if r.Discovery == nil || r.Signaler == nil {
		t.Fatal("missing built-in capabilities")
	}
	providers, e := SourceDiscoveryFromConfig(cfg, s.Client())
	if e != nil {
		t.Fatal(e)
	}
	v := RootVerifier{Providers: map[string]domain.SourceDiscoveryProvider{"u": providers[0].Provider}}
	for range 2 {
		if _, e = v.Verify(context.Background(), []sources.Binding{{ProviderID: "u", ConsoleID: "console"}}); e != nil {
			t.Fatal(e)
		}
	}
	if wanCalls != 2 {
		t.Fatal("root verifier used cache")
	}
	before := wanCalls
	if _, e = r.Signaler.Encode(context.Background(), domain.VLANAssignment{ID: 30, LocationID: "office"}, domain.TrustedNetworkContext{LocationID: "office", Medium: domain.WiFi}); e != nil {
		t.Fatal(e)
	}
	if wanCalls != before {
		t.Fatal("auth path performed WAN lookup")
	}
	cfg.Network.Providers[0].Timeout = 2 * time.Minute
	if _, e = NetworkServiceFromConfig(cfg, new(network.Store), true, s.Client()); e == nil {
		t.Fatal("unbounded timeout accepted")
	}
}
func TestSourcesRuntimeRequiresFixedProtectedRootEntry(t *testing.T) {
	called := false
	s := NewRuntimeServices()
	s.SourceDependencies = func(context.Context, config.Config) (sources.Verifier, sources.Operations, error) {
		called = true
		return nil, nil, nil
	}
	e := s.Run(context.Background(), OperationSourcesApply, config.Defaults(), RunOptions{ConfigFile: "/tmp/caller-config", DryRun: true})
	if e == nil || called {
		t.Fatal("caller config reached privileged dependencies")
	}
}
func TestClaimedSourceDigestCannotApplyReplacement(t *testing.T) {
	c := []domain.SourceCandidate{{ProviderID: "u", SiteID: "console", CIDRs: []string{"8.8.8.8/32"}, ObservedAt: domain.Unix(time.Now())}}
	raw, _ := json.Marshal(c)
	hash := sha256.Sum256(raw)
	digest := hex.EncodeToString(hash[:])
	if e := checkSourceDigest(c, digest); e != nil {
		t.Fatal(e)
	}
	c[0].CIDRs = []string{"9.9.9.9/32"}
	if e := checkSourceDigest(c, digest); e == nil {
		t.Fatal("replacement candidate accepted under old claim")
	}
	if e := checkSourceDigest(c, "../../executable"); e == nil {
		t.Fatal("unvalidated digest accepted")
	}
}
