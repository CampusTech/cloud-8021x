package fleet

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/inventory"
)

func TestCollectorScopeExemptionAndCredentials(t *testing.T) {
	ca, _ := certFixture(t)
	trust, _ := NewTrust(ca)
	mutations := 0
	now := time.Now()
	var mu sync.Mutex
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method != "GET" {
			mutations++
			t.Error("ineligible host caused submission")
		}
		if r.Header.Get("Authorization") != "Bearer maintainer" {
			t.Error("collector used observer token")
		}
		if r.URL.Path == "/api/v1/fleet/hosts" {
			_, _ = w.Write([]byte(`{"hosts":[{"id":1,"uuid":"host","platform":"darwin"},{"id":2,"uuid":"outside","platform":"darwin"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"host":{"id":1,"uuid":"host","platform":"darwin","os_version":"14.0","last_mdm_enrolled_at":"` + now.Add(-time.Hour).Format(time.RFC3339) + `","last_enrolled_at":"` + now.Add(-time.Hour).Format(time.RFC3339) + `","mdm":{"enrollment_status":"On (automatic)","profiles":[{"profile_uuid":"acme","status":"verified","operation_type":"install"}]}}}`))
	}))
	defer srv.Close()
	client, _ := NewClient(srv.URL, "maintainer", srv.Client(), time.Second)
	batch := domain.DeviceSnapshot{Scope: domain.InventoryScope{ProviderID: "fleet", IDs: []string{"1"}}, Complete: true, ObservedAt: domain.Unix(now), Devices: []domain.Device{{ID: "fleet:1", Identities: []string{"host"}, Groups: []domain.GroupID{}, Enrolled: true}}}
	for _, opts := range []CollectionOptions{{ACMEProfiles: []string{"acme"}}, {SCEPProfiles: []string{}}} {
		collector := Collector{Maintainer: client, Trust: trust, Options: opts, Now: func() time.Time { return now }}
		if err := collector.Prepare(context.Background(), batch); err != nil {
			t.Fatal(err)
		}
		if _, err := collector.Collect(context.Background(), domain.CertificateCollectionRequest{DeviceID: "fleet:2"}); !errors.Is(err, inventory.ErrIneligible) {
			t.Fatalf("scope escaped %v", err)
		}
		if _, err := collector.Collect(context.Background(), domain.CertificateCollectionRequest{DeviceID: "fleet:1"}); !errors.Is(err, inventory.ErrIneligible) {
			t.Fatalf("minimum scope escaped %v", err)
		}
	}
	if mutations != 0 {
		t.Fatal("ACME exemption polled")
	}
}

func TestManagedOnlyRequiresSupportedOS(t *testing.T) {
	ca, _ := certFixture(t)
	trust, _ := NewTrust(ca)
	now := time.Now()
	version := "10.14.6"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"host":{"id":1,"uuid":"host","platform":"darwin","os_version":"` + version + `","last_mdm_enrolled_at":"` + now.Add(-time.Hour).Format(time.RFC3339) + `","mdm":{"enrollment_status":"On (automatic)"}}}`))
	}))
	defer srv.Close()
	client, _ := NewClient(srv.URL, "maintainer", srv.Client(), time.Second)
	collector := Collector{Maintainer: client, Trust: trust, hosts: map[domain.DeviceID]host{"fleet:1": {ID: 1, UUID: "host", Platform: "darwin"}}}
	for _, v := range []string{"", "unknown", "10.14.6"} {
		version = v
		if _, _, err := collector.boundHost(context.Background(), "fleet:1"); !errors.Is(err, inventory.ErrIneligible) {
			t.Fatalf("unsupported ManagedOnly OS %q accepted: %v", v, err)
		}
	}
	version = "10.15.7"
	if _, r, err := collector.boundHost(context.Background(), "fleet:1"); err != nil || !r.ManagedOnly {
		t.Fatalf("supported ManagedOnly rejected %v", err)
	}
}

func TestWindowsTerminalFailureRequiresExactProvenance(t *testing.T) {
	ca, _ := certFixture(t)
	trust, _ := NewTrust(ca)
	now := time.Now()
	wrong := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := 1
		if wrong {
			id = 2
		}
		_, _ = w.Write([]byte(`{"host_id":` + itoa(id) + `,"execution_id":"execution","script_contents":"exact nonce script","exit_code":1,"created_at":"` + now.Truncate(time.Second).Format(time.RFC3339) + `","output":"failure"}`))
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "maintainer", server.Client(), time.Second)
	collector := Collector{Maintainer: client, Trust: trust, Now: func() time.Time { return now }}
	r := reservation{UUID: "nonce", HostID: 1, HostUUID: "host", ExecutionID: "execution", Transport: "windows", Script: "exact nonce script", EnrolledAt: float64(now.Add(-time.Hour).Unix()), CreatedAt: float64(now.Add(-time.Minute).Unix())}
	if ob, terminal, err := collector.poll(context.Background(), r, time.Hour); err != nil || !terminal || ob != nil {
		t.Fatalf("authenticated terminal failure retained pending slot: %v %v", terminal, err)
	}
	wrong = true
	if _, terminal, err := collector.poll(context.Background(), r, time.Hour); err == nil || terminal {
		t.Fatal("wrong host failure freed a reservation")
	}
}
