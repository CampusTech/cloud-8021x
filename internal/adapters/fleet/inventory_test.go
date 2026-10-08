package fleet

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

func TestObserverPaginationScopeAndAliases(t *testing.T) {
	pages := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer observer" || r.Method != "GET" || r.URL.Query().Get("device_mapping") != "true" {
			t.Error("observer credential/operation escaped")
		}
		pages++
		var hosts []map[string]any
		if r.URL.Query().Get("page") == "0" {
			hosts = []map[string]any{{"id": 1, "uuid": "{0123456789ABCDEF0123456789ABCDEF}", "team_id": 4, "hardware_serial": "", "display_name": "Mac", "hardware_model": "Model", "device_mapping": []map[string]string{{"email": "owner@example.invalid"}}, "mdm": map[string]string{"enrollment_status": "On (automatic)"}}, {"id": 2, "uuid": "other", "team_id": 8}}
		} else {
			hosts = []map[string]any{}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"hosts": hosts})
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "observer", server.Client(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	observer := Observer{Client: client, PageSize: 2, HostIDs: []string{"1"}, TeamIDs: []string{"4"}, Now: func() time.Time { return time.Unix(100, 125000000) }}
	scope := domain.InventoryScope{ProviderID: "fleet", IDs: []string{"1", "2"}}
	batch, err := observer.Fetch(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if !batch.Complete || pages != 2 || batch.ObservedAt != 100.125 || !reflect.DeepEqual(batch.Scope, scope) || len(batch.Devices) != 1 {
		t.Fatalf("pagination %+v %d", batch, pages)
	}
	d := batch.Devices[0]
	if d.ID != "fleet:1" || d.Groups[0] != "fleet:4" || d.Identities[0] != "01234567-89ab-cdef-0123-456789abcdef" || d.Metadata.Owner != "owner@example.invalid" || d.Fingerprints != nil {
		t.Fatalf("normalization %+v", d)
	}
	scope.IDs = []string{}
	batch, err = observer.Fetch(context.Background(), scope)
	if err != nil || len(batch.Devices) != 0 {
		t.Fatalf("explicit empty scope %+v %v", batch, err)
	}
}
func TestObserverIncompleteDuplicateRateLimitAndCancellation(t *testing.T) {
	for _, mode := range []string{"partial", "duplicate", "rate", "cancel", "oversized", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				switch mode {
				case "rate":
					w.Header().Set("Retry-After", "0")
					w.WriteHeader(429)
				case "cancel":
					cancel()
					<-r.Context().Done()
				case "oversized":
					_, _ = w.Write([]byte(strings.Repeat("x", MaxResponseBytes+1)))
				case "malformed":
					_, _ = w.Write([]byte(`{"hosts":[],"hosts":[]}`))
				default:
					if r.URL.Query().Get("page") == "1" && mode == "partial" {
						w.WriteHeader(500)
					} else {
						_, _ = w.Write([]byte(`{"hosts":[{"id":1,"uuid":"one"}]}`))
					}
				}
			}))
			defer srv.Close()
			c, _ := NewClient(srv.URL, "observer", srv.Client(), time.Second)
			p := Observer{Client: c, PageSize: 1}
			b, err := p.Fetch(ctx, domain.InventoryScope{ProviderID: "fleet"})
			if err == nil || b.Complete {
				t.Fatalf("partial accepted %+v %v", b, err)
			}
			if mode == "rate" && calls != 3 {
				t.Fatalf("unbounded/missing retry %d", calls)
			}
		})
	}
}
func TestClientRejectsCredentialRedirectAndMutatingRetry(t *testing.T) {
	leaked := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer target.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer srv.Close()
	c, _ := NewClient(srv.URL, "secret", srv.Client(), time.Second)
	var out map[string]any
	if err := c.request(context.Background(), "GET", "/api/v1/fleet/hosts", nil, &out); err == nil || leaked {
		t.Fatal("redirect forwarded bearer")
	}
	for _, base := range []string{"http://localhost", "https://user:pass@example.invalid", "https://example.invalid/path", "https://example.invalid?token=x"} {
		if _, err := NewClient(base, "secret", nil, time.Second); err == nil {
			t.Fatalf("unsafe base %s", base)
		}
	}
}
