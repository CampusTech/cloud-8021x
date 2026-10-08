package unifi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

func TestPinnedWANFetchAndPagination(t *testing.T) {
	calls := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("X-API-Key") != "synthetic" {
			t.Error("missing key")
		}
		if r.URL.Path != "/v1/hosts" {
			t.Error(r.URL.Path)
		}
		if r.URL.Query().Get("nextToken") == "next" {
			_, _ = w.Write([]byte(`{"data":[{"id":"office","updatedAt":"old","reportedState":{"wans":[{"ipv4":"8.8.4.4"},{"ipv4":"10.0.0.1"}]},"ipAddress":"8.8.8.8"}]}`))
		} else {
			_, _ = w.Write([]byte(`{"data":[],"nextToken":"next"}`))
		}
	}))
	defer s.Close()
	c, err := New("u", s.URL+"/v1", "synthetic", s.Client(), time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.DiscoverSources(context.Background(), domain.InventoryScope{ProviderID: "u", IDs: []string{"office"}})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(got) != 1 || len(got[0].CIDRs) != 2 || !domain.Fresh(got[0].ObservedAt, time.Now(), time.Minute) {
		t.Fatalf("bad discovery %+v calls %d", got, calls)
	}
}
func TestInventoryScopedSitePortsAndMissingHome(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := "/v1/connector/consoles/console/proxy/network/integration/v1/sites"
		switch r.URL.Path {
		case prefix:
			_, _ = w.Write([]byte(`{"data":[{"id":"office","name":"32 Avenue of the Americas"}],"offset":0,"count":1,"totalCount":1}`))
		case prefix + "/office/devices":
			_, _ = w.Write([]byte(`{"data":[{"id":"switch"}],"offset":0,"count":1,"totalCount":1}`))
		case prefix + "/office/devices/switch":
			_, _ = w.Write([]byte(`{"id":"switch","name":"Switch","macAddress":"aa:bb:cc:dd:ee:ff","interfaces":{"ports":[{"idx":1},{"idx":2}]}}`))
		case prefix + "/office/networks":
			_, _ = w.Write([]byte(`{"data":[{"id":"staff","name":"Staff","vlanId":20}],"offset":0,"count":1,"totalCount":1}`))
		default:
			t.Error(r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer s.Close()
	c, _ := New("u", s.URL+"/v1", "synthetic", s.Client(), time.Second, nil)
	c.ConsoleID = "console"
	b, e := c.Fetch(context.Background(), domain.InventoryScope{ProviderID: "u", IDs: []string{"office", "home"}})
	if e != nil {
		t.Fatal(e)
	}
	if b.Scopes[0].Status != domain.CapabilityAvailable || b.Scopes[1].Status != domain.CapabilityFailed || len(b.Authenticators) != 1 || len(b.Authenticators[0].Ports) != 2 || b.Sites[0].Name != "32 Avenue of the Americas" {
		t.Fatalf("bad scope normalization %+v", b)
	}
}
func TestRepeatedTokensMissingAndDuplicateHosts(t *testing.T) {
	for _, body := range []string{`{"data":[],"nextToken":"repeat"}`, `{"data":[]}`, `{"data":[{"id":"office","ipAddress":"8.8.8.8"},{"id":"office","ipAddress":"8.8.4.4"}]}`, `{"data":[{"id":"office","ipAddress":"10.0.0.1"}]}`, `{"data":[{"id":"office","ipAddress":"8.8.8.8","isBlocked":true}]}`} {
		t.Run(body, func(t *testing.T) {
			calls := 0
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; _, _ = w.Write([]byte(body)) }))
			defer s.Close()
			c, _ := New("u", s.URL+"/v1", "synthetic", s.Client(), time.Second, nil)
			c.ConsoleID = "office"
			if _, e := c.DiscoverSources(context.Background(), domain.InventoryScope{ProviderID: "u", IDs: []string{"office"}}); e == nil {
				t.Fatal("unsafe discovery accepted")
			}
			if calls > 2 {
				t.Fatal("unbounded repeated token")
			}
		})
	}
}
func TestInventoryPaginationRejectsChangingTotalsAndRepeatedIDs(t *testing.T) {
	for _, body := range []string{`{"data":[{"id":"s"},{"id":"s"}],"offset":0,"count":2,"totalCount":2}`, `{"data":[],"offset":1,"count":0,"totalCount":0}`, `{"data":[],"offset":0,"count":0,"totalCount":1}`, `{"data":[{"id":"s"}],"offset":0,"count":0,"totalCount":1}`} {
		t.Run(body, func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer s.Close()
			c, _ := New("u", s.URL+"/v1", "synthetic", s.Client(), time.Second, nil)
			c.ConsoleID = "console"
			b, e := c.Fetch(context.Background(), domain.InventoryScope{ProviderID: "u", IDs: []string{"s"}})
			if e != nil {
				t.Fatal(e)
			}
			if len(b.Scopes) != 1 || b.Scopes[0].Status != domain.CapabilityFailed {
				t.Fatal("partial inventory marked successful")
			}
		})
	}
}
func TestUniFiInferredBSSIDsAreBoundedAndExplicit(t *testing.T) {
	got := inferredBSSIDs("AABBCCDDEEFA")
	if len(got) != 5 || got[0] != "AABBCCDDEEFB" || got[4] != "AABBCCDDEEFF" {
		t.Fatal("inference crossed last-byte boundary", got)
	}
	if len(inferredBSSIDs("AABBCCDDEEFF")) != 0 {
		t.Fatal("inference wrapped octet")
	}
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "/v1/connector/consoles/console/proxy/network/integration/v1/sites"
		switch r.URL.Path {
		case base:
			_, _ = w.Write([]byte(`{"data":[{"id":"office","name":"Office"}],"offset":0,"count":1,"totalCount":1}`))
		case base + "/office/devices":
			_, _ = w.Write([]byte(`{"data":[{"id":"ap"}],"offset":0,"count":1,"totalCount":1}`))
		case base + "/office/devices/ap":
			_, _ = w.Write([]byte(`{"id":"ap","name":"AP","macAddress":"aa:bb:cc:dd:ee:01","features":{"accessPoint":{}}}`))
		case base + "/office/networks":
			_, _ = w.Write([]byte(`{"data":[],"offset":0,"count":0,"totalCount":0}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer s.Close()
	c, _ := New("u", s.URL+"/v1", "synthetic", s.Client(), time.Second, nil)
	c.ConsoleID = "console"
	b, e := c.Fetch(context.Background(), domain.InventoryScope{ProviderID: "u", IDs: []string{"office"}})
	if e != nil || len(b.Authenticators) != 1 || len(b.Authenticators[0].InferredMACs) != 7 || len(b.Authenticators[0].MACs) != 0 {
		t.Fatalf("inferred aliases missing or labeled advertised %+v %v", b, e)
	}
}
