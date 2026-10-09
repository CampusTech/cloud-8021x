package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/unifi"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
)

func TestSemanticDisplayToleratesOnlyRenderingEquivalentRefresh(t *testing.T) {
	c := config.Defaults()
	s := domain.Snapshot{Version: 2, UpdatedAt: domain.Unix(time.Now().Add(-time.Minute)), Identities: map[string]*domain.DeviceRecord{}, Certificates: map[string]*domain.DeviceRecord{}, HardwareSerials: map[string]*domain.DeviceRecord{}, Devices: map[domain.DeviceID]*domain.DeviceMetadata{"fleet:1": {}, "fleet:2": {}}}
	first, err := semanticDisplay(c, s)
	if err != nil {
		t.Fatal(err)
	}
	s.UpdatedAt = domain.Unix(time.Now())
	next, err := semanticDisplay(c, s)
	if err != nil || next != first {
		t.Fatal("timestamp-only refresh changed equivalent display")
	}
	s.Devices["fleet:2"] = &domain.DeviceMetadata{Name: "new meaningful display"}
	if _, err := semanticDisplay(c, s); err == nil {
		t.Fatal("changed historical display inferred without proof")
	}
}

func neutralProviderConfig() config.Config {
	c := config.Defaults()
	c.Network.Providers = []config.NetworkProvider{{ID: "task11-unifi", Kind: "unifi", BaseURL: "https://unifi.task11.test/v1", ConsoleID: "task11-console", Scopes: []string{"task11-site"}, Credential: config.SecretRef{File: "/run/cloud-8021x/credentials/unifi-token"}, CacheFile: "/var/cache/cloud-8021x/runtime/task11-unifi.json", Timeout: 5 * time.Second}}
	c.Network.Locations = []config.Location{{ID: "task11", ProviderID: "task11-unifi", SiteID: "task11-site", VLANEnabled: true}}
	c.RadiusClients = []config.RadiusClient{{ID: "task11-nas", CIDRs: []string{"10.203.11.40/32"}, LocationID: "task11", Medium: "wifi", SignalingProfile: "unifi-numeric", Secret: config.SecretRef{File: "/run/cloud-8021x-root/radius-task11-secret"}}}
	c.Policy.Rules = []config.VLANRule{{GroupID: "fleet:1", LocationID: "task11", VLAN: 120}}
	return c
}
func TestExactNeutralProviderIsRenderingEquivalent(t *testing.T) {
	c := neutralProviderConfig()
	s := domain.Snapshot{Version: 2, UpdatedAt: domain.Unix(time.Now()), Identities: map[string]*domain.DeviceRecord{}, Certificates: map[string]*domain.DeviceRecord{}, HardwareSerials: map[string]*domain.DeviceRecord{}}
	if _, err := semanticDisplay(c, s); err != nil {
		t.Fatal("actual required provider rejected", err)
	}
	for _, change := range []func(*config.Config){func(v *config.Config) { v.Network.Providers[0].BaseURL = "https://other.task11.test/v1" }, func(v *config.Config) { v.Network.Discovery.Enabled = true }, func(v *config.Config) { v.Policy.Rules[0].VLAN = 121 }, func(v *config.Config) { v.RadiusClients[0].CIDRs = []string{"10.203.11.0/24"} }} {
		bad := neutralProviderConfig()
		change(&bad)
		if _, err := semanticDisplay(bad, s); err == nil {
			t.Fatal("broadened provider authority accepted")
		}
	}
}

type neutralTransport func(*http.Request) (*http.Response, error)

func (f neutralTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestActualUniFiNeutralPagesAndStoredMetadataRemainEquivalent(t *testing.T) {
	c := neutralProviderConfig()
	now := time.Now().UTC()
	base := "/v1/connector/consoles/task11-console/proxy/network/integration/v1/sites"
	replies := map[string]string{base + "?limit=200&offset=0": `{"data":[{"id":"task11-site","name":"N/A"}],"offset":0,"count":1,"totalCount":1}`, base + "/task11-site/devices?limit=200&offset=0": `{"data":[],"offset":0,"count":0,"totalCount":0}`, base + "/task11-site/networks?limit=200&offset=0": `{"data":[],"offset":0,"count":0,"totalCount":0}`}
	seen := 0
	hc := &http.Client{Transport: neutralTransport(func(r *http.Request) (*http.Response, error) {
		body, ok := replies[r.URL.RequestURI()]
		if !ok || r.Method != "GET" || r.URL.Host != "unifi.task11.test" || r.Header.Get("X-API-Key") != "synthetic" {
			return nil, errors.New("unexpected actual adapter request")
		}
		seen++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	client, err := unifi.New("task11-unifi", c.Network.Providers[0].BaseURL, "synthetic", hc, time.Second, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	client.ConsoleID = "task11-console"
	batch, err := client.Fetch(context.Background(), domain.InventoryScope{ProviderID: "task11-unifi", IDs: []string{"task11-site"}})
	if err != nil || seen != 3 {
		t.Fatal("actual adapter pages", seen, err)
	}
	s := domain.Snapshot{Version: 2, UpdatedAt: domain.Unix(now), Identities: map[string]*domain.DeviceRecord{}, Certificates: map[string]*domain.DeviceRecord{}, HardwareSerials: map[string]*domain.DeviceRecord{}}
	want, err := semanticDisplay(c, s)
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []domain.Timestamp{domain.Unix(now), domain.Unix(now.Add(-48 * time.Hour))} {
		batch.Scopes[0].ObservedAt = at
		batch.Scopes[0].VLANObservedAt = at
		got, e := semanticDisplay(c, s, batch)
		if e != nil || got != want {
			t.Fatal("actual neutral metadata changed expected display", e)
		}
	}
	batch.Sites[0].Name = "meaningful-history"
	if _, err = semanticDisplay(c, s, batch); err == nil {
		t.Fatal("changed historical site metadata accepted")
	}
}
