package app

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	radiuspolicy "github.com/CampusTech/cloud-8021x/internal/adapters/freeradius/policy"
	"github.com/CampusTech/cloud-8021x/internal/adapters/network/signaling"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	core "github.com/CampusTech/cloud-8021x/internal/policy"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
)

func TestLifecycleDatabaseOutageKeepsFreshLocalPolicyAndDeniesStale(t *testing.T) {
	// A real local TCP endpoint accepts then drops PostgreSQL connections. There
	// is no remote service or production DSN, and no fake successful DB response.
	db, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var dbAttempts atomic.Int32
	go func() {
		for {
			c, e := db.Accept()
			if e != nil {
				return
			}
			dbAttempts.Add(1)
			_ = c.Close()
		}
	}()
	tlsFixture := httptest.NewTLSServer(http.NotFoundHandler())
	defer tlsFixture.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsFixture.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	dbCfg := config.Defaults().Database
	dbCfg.CAFile = ca
	dbCfg.ConnectTimeout = time.Second
	dbCfg.QueryTimeout = time.Second
	repository, err := postgres.New(context.Background(), "postgres://fixture:fixture@"+db.Addr().String()+"/cloud8021x", dbCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	worker := repository.ForTransition(strings.Repeat("a", 64))
	now := time.Now()
	snapshots := new(domain.SnapshotStore)
	snapshot, err := domain.BuildSnapshot([]domain.Device{{ID: "other:1", Identities: []string{"SERIAL"}, Enrolled: true, Groups: []domain.GroupID{"other:staff"}}}, domain.Unix(now))
	if err != nil {
		t.Fatal(err)
	}
	if err = snapshots.Set(snapshot); err != nil {
		t.Fatal(err)
	}
	engine, err := core.New(core.Config{IdentityMode: core.LegacySerialMode, InventoryMaxAge: time.Hour, CertificateMaxAge: time.Hour, Locations: []core.Location{{ID: "office", VLANEnabled: true}}, Rules: []core.Rule{{GroupID: "other:staff", LocationID: "office", VLAN: 120}}})
	if err != nil {
		t.Fatal(err)
	}
	trust, err := core.NewTrustMap([]core.Client{{ID: "ap", LocationID: "office", CIDRs: []string{"192.0.2.0/24"}, Medium: domain.WiFi, SignalingProfile: "unifi-numeric"}})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signaling.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	service, err := radiuspolicy.NewLocalService(radiuspolicy.ServiceOptions{Engine: engine, Snapshots: snapshots, Trust: trust, Signaling: sig})
	if err != nil {
		t.Fatal(err)
	}
	token := bytes.Repeat([]byte("k"), 32)
	handler, err := radiuspolicy.NewHandler(radiuspolicy.HTTPOptions{Token: token, MaxConcurrency: 8, MaxBodyBytes: 4096, Timeout: time.Second, Service: service})
	if err != nil {
		t.Fatal(err)
	}
	addresses := make(chan string, 1)
	server := handler.Server("127.0.0.1:0")
	server.BaseContext = func(l net.Listener) context.Context { addresses <- l.Addr().String(); return context.Background() }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	failed := make(chan struct{}, 1)
	ready := make(chan struct{}, 1)
	var address atomic.Value
	lifecycle := lifecycle{Servers: []*http.Server{server}, Ready: func(ctx context.Context) error {
		v := address.Load()
		if v == nil {
			return errors.New("listener starting")
		}
		return probePolicyHandler(ctx, v.(string), token)
	}, Notify: func(s string) error {
		if s == "READY=1" {
			ready <- struct{}{}
		}
		return nil
	}, Jobs: []scheduledJob{{Name: "outage", Interval: time.Hour, Timeout: 2 * time.Second, Run: func(ctx context.Context) error {
		err := worker.Reserve(ctx, "never", "outbox", json.RawMessage(`{}`))
		if err != nil {
			failed <- struct{}{}
		}
		return err
	}}}}
	done := make(chan error, 1)
	go func() { done <- lifecycle.Run(ctx) }()
	select {
	case v := <-addresses:
		address.Store(v)
	case <-time.After(2 * time.Second):
		t.Fatal("listener absent")
	}
	for _, ch := range []chan struct{}{failed, ready} {
		select {
		case <-ch:
		case <-time.After(3 * time.Second):
			t.Fatal("DB outage blocked local readiness")
		}
	}
	check := func(want int) {
		t.Helper()
		raw, _ := json.Marshal(radiuspolicy.Request{Server: radiuspolicy.ServerContext{ClientID: "ap", SourceIP: "192.0.2.4"}, CertificateCommonNames: []string{"SERIAL"}, NASPortTypes: []string{"19"}})
		req, e := http.NewRequest("POST", "http://"+address.Load().(string)+"/authorize", bytes.NewReader(raw))
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Authorization", "Bearer "+string(token))
		req.Header.Set("Content-Type", "application/json")
		response, e := (&http.Client{Timeout: time.Second}).Do(req)
		if e != nil {
			t.Fatal(e)
		}
		_ = response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("policy status=%d want %d", response.StatusCode, want)
		}
	}
	check(200)
	snapshot.UpdatedAt = domain.Unix(now.Add(-2 * time.Hour))
	if err = snapshots.Set(snapshot); err != nil {
		t.Fatal(err)
	}
	check(403)
	if dbAttempts.Load() == 0 {
		t.Fatal("database outage was not exercised")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("outage prevented shutdown")
	}
}
