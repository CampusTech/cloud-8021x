package meraki

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/network"
)

func TestScopedPaginatedMACVLANAndSwitchInventory(t *testing.T) {
	var base string
	calls := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer synthetic" {
			t.Error("missing credential")
		}
		switch r.URL.Path {
		case "/api/v1/organizations/org/devices":
			if r.URL.Query().Get("startingAfter") == "second" {
				_, _ = w.Write([]byte(`[{"serial":"switch","networkId":"office","mac":"1122.3344.5566","name":"Switch","productType":"switch"}]`))
			} else {
				w.Header().Set("Link", fmt.Sprintf(`<%s/api/v1/organizations/org/devices?startingAfter=second>; rel="next"`, base))
				_, _ = w.Write([]byte(`[{"serial":"ap","networkId":"office","mac":"aa:bb:cc:dd:ee:ff","name":"AP","productType":"wireless"},{"serial":"ap","networkId":"elsewhere","mac":"aa:bb:cc:dd:ee:ff","name":"Wrong"}]`))
			}
		case "/api/v1/organizations/org/wireless/ssids/statuses/byDevice":
			_, _ = w.Write([]byte(`{"items":[{"serial":"ap","name":"Office AP","network":{"id":"office","name":"Sacramento"},"basicServiceSets":[{"bssid":"AA-BB-CC-DD-EE-F0"}]}]}`))
		case "/api/v1/networks/office":
			_, _ = w.Write([]byte(`{"id":"office","name":"Sacramento","productTypes":["wireless","switch"]}`))
		case "/api/v1/networks/office/vlanProfiles":
			_, _ = w.Write([]byte(`[{"vlanNames":[{"vlanId":"10","name":"Staff"}]}]`))
		case "/api/v1/devices/switch/switch/ports":
			_, _ = w.Write([]byte(`[{"portId":"1"},{"portId":"2"}]`))
		case "/api/v1/networks/home":
			http.Error(w, "secret body", http.StatusForbidden)
		default:
			t.Error("unexpected path", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer s.Close()
	base = s.URL
	c, e := New("m", "org", base+"/api/v1", "synthetic", s.Client(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	scope := domain.InventoryScope{ProviderID: "m", IDs: []string{"office", "home"}}
	b, e := c.Fetch(context.Background(), scope)
	if e != nil {
		t.Fatal(e)
	}
	if b.Scopes[0].Status != domain.CapabilityAvailable || b.Scopes[1].Status != domain.CapabilityFailed {
		t.Fatal(b.Scopes)
	}
	store := new(network.Store)
	if e = store.Publish(b); e != nil {
		t.Fatal(e)
	}
	for _, mac := range []string{"aa:bb:cc:dd:ee:ff:Campus", "AA-BB-CC-DD-EE-F0:Campus"} {
		got := store.Resolve("m", "office", mac, 10, time.Now(), time.Hour)
		if got.Authenticator != "Office AP" || got.Site != "Sacramento" || got.VLAN != "Staff" {
			t.Fatal(got)
		}
	}
	if got := store.Resolve("m", "office", "AABBCCDDEEF1", 0, time.Now(), time.Hour); got.Authenticator != "" {
		t.Fatal("guessed BSSID offset")
	}
	if len(store.Ports("m", "office", "m/office/switch", time.Now(), time.Hour)) != 2 {
		t.Fatal("missing switch ports")
	}
	before := calls
	if _, e = c.Encode(context.Background(), domain.VLANAssignment{ID: 10, LocationID: "office"}, domain.TrustedNetworkContext{LocationID: "office", Medium: domain.WiFi}); e != nil {
		t.Fatal(e)
	}
	if calls != before {
		t.Fatal("signaling fetched inventory")
	}
}
func TestMerakiHostileAndRepeatedLink(t *testing.T) {
	for _, mode := range []string{"repeat", "cross", "path", "ambiguous"} {
		t.Run(mode, func(t *testing.T) {
			var base string
			calls := 0
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				next := base + r.URL.RequestURI()
				switch mode {
				case "cross":
					next = "https://outside.invalid/api/v1/organizations/org/devices"
				case "path":
					next = base + "/api/v1/else"
				}
				link := "<" + next + ">; rel=next"
				if mode == "ambiguous" {
					link += ", " + link
				}
				w.Header().Set("Link", link)
				_, _ = w.Write([]byte(`[]`))
			}))
			defer s.Close()
			base = s.URL
			c, _ := New("m", "org", base+"/api/v1", "synthetic", s.Client(), time.Second)
			_, e := c.Fetch(context.Background(), domain.InventoryScope{ProviderID: "m", IDs: []string{"office"}})
			if e == nil || calls != 1 || strings.Contains(e.Error(), "synthetic") {
				t.Fatalf("unsafe paging %v %d", e, calls)
			}
		})
	}
}
func TestAmbiguousHardwareJoinNeverLabelsEitherMAC(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/organizations/org/devices":
			_, _ = w.Write([]byte(`[{"serial":"ap","networkId":"office","mac":"AABBCCDDEE01","name":"AP"},{"serial":"ap","networkId":"office","mac":"AABBCCDDEE02","name":"AP"},{"serial":"ap","networkId":"office","mac":"AABBCCDDEE01","name":"AP"}]`))
		case "/api/v1/organizations/org/wireless/ssids/statuses/byDevice":
			_, _ = w.Write([]byte(`{"items":[{"serial":"ap","name":"AP","network":{"id":"office","name":"Office"},"basicServiceSets":[]}]}`))
		case "/api/v1/networks/office":
			_, _ = w.Write([]byte(`{"id":"office","name":"Office","productTypes":["wireless"]}`))
		case "/api/v1/networks/office/vlanProfiles":
			_, _ = w.Write([]byte(`[]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer s.Close()
	c, _ := New("m", "org", s.URL+"/api/v1", "synthetic", s.Client(), time.Second)
	b, e := c.Fetch(context.Background(), domain.InventoryScope{ProviderID: "m", IDs: []string{"office"}})
	if e != nil {
		t.Fatal(e)
	}
	store := new(network.Store)
	if e = store.Publish(b); e != nil {
		t.Fatal(e)
	}
	for _, mac := range []string{"AABBCCDDEE01", "AABBCCDDEE02"} {
		if store.Resolve("m", "office", mac, 0, time.Now(), time.Hour).Authenticator != "" {
			t.Fatal("ambiguous serial mapping attributed", mac)
		}
	}
}
func TestUnknownVLAN404IsFailedNotFreshEmpty(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/organizations/org/devices":
			_, _ = w.Write([]byte(`[]`))
		case "/api/v1/organizations/org/wireless/ssids/statuses/byDevice":
			_, _ = w.Write([]byte(`{"items":[]}`))
		case "/api/v1/networks/office":
			_, _ = w.Write([]byte(`{"id":"office","name":"Office","productTypes":["wireless"]}`))
		default:
			http.Error(w, "not found", 404)
		}
	}))
	defer s.Close()
	c, _ := New("m", "org", s.URL+"/api/v1", "synthetic", s.Client(), time.Second)
	b, e := c.Fetch(context.Background(), domain.InventoryScope{ProviderID: "m", IDs: []string{"office"}})
	if e != nil || len(b.Scopes) != 1 || b.Scopes[0].Status != domain.CapabilityAvailable || b.Scopes[0].VLANStatus != domain.CapabilityFailed {
		t.Fatalf("404 erased VLAN scope %+v %v", b, e)
	}
}
func TestExplicitUnsupportedVersusMissingCapabilityShape(t *testing.T) {
	for _, tc := range []struct {
		products string
		want     domain.CapabilityStatus
	}{{`,"productTypes":["camera"]`, domain.CapabilityUnsupported}, {``, domain.CapabilityFailed}, {`,"productTypes":["wireless"]`, domain.CapabilityAvailable}} {
		t.Run(string(tc.want), func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/organizations/org/devices":
					_, _ = w.Write([]byte(`[]`))
				case "/api/v1/organizations/org/wireless/ssids/statuses/byDevice":
					_, _ = w.Write([]byte(`{"items":[]}`))
				case "/api/v1/networks/office":
					_, _ = w.Write([]byte(`{"id":"office","name":"Office"` + tc.products + `}`))
				case "/api/v1/networks/office/vlanProfiles":
					_, _ = w.Write([]byte(`[]`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer s.Close()
			c, _ := New("m", "org", s.URL+"/api/v1", "synthetic", s.Client(), time.Second)
			b, e := c.Fetch(context.Background(), domain.InventoryScope{ProviderID: "m", IDs: []string{"office"}})
			if e != nil || len(b.Scopes) != 1 || b.Scopes[0].Status != tc.want {
				t.Fatal("unsupported/empty/failed conflated", b, e)
			}
		})
	}
}
