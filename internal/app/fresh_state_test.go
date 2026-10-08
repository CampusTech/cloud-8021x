package app

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
)

func TestFreshInventoryOnlyObserverGETAndNoCertificateAuthority(t *testing.T) {
	for _, scenario := range []string{"observed", "empty", "failure"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "GET" || r.URL.Path != "/api/v1/fleet/hosts" || r.Header.Get("Authorization") != "Bearer observer-only" {
					t.Fatal("unexpected privileged/API action", r.Method, r.URL.Path)
				}
				switch scenario {
				case "empty":
					_, _ = w.Write([]byte(`{"hosts":[]}`))
				case "failure":
					w.WriteHeader(503)
				default:
					_, _ = w.Write([]byte(`{"hosts":[{"id":1,"uuid":"original-host","hardware_serial":"SERIAL","team_id":1,"mdm":{"enrollment_status":"On (automatic)"}}]}`))
				}
			}))
			defer server.Close()
			cfg := config.Defaults()
			cfg.Inventory.Enabled = true
			cfg.Inventory.Fleet.BaseURL = server.URL
			cfg.Inventory.Fleet.ManagedCertificates = true
			cfg.Policy.IdentityMode = "fingerprint"
			before := domain.Unix(time.Now())
			raw, e := fetchFreshInventory(context.Background(), cfg, []byte("observer-only"), server.Client())
			if scenario != "observed" {
				if e == nil {
					t.Fatal("unavailable observer became authority")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			s, e := domain.DecodeSnapshot(bytes.NewReader(raw))
			if e != nil || s.UpdatedAt < before || s.UpdatedAt > domain.Unix(time.Now()) || len(s.Certificates) != 0 || len(s.HardwareSerials) != 0 || len(s.Identities) == 0 || calls != 1 {
				t.Fatal("invented certificate/time or scope", s, e, calls)
			}
		})
	}
}
