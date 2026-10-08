package postgres

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	fleetadapter "github.com/CampusTech/cloud-8021x/internal/adapters/fleet"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/inventory"
	inventoryjob "github.com/CampusTech/cloud-8021x/internal/jobs/inventory"
	"howett.net/plist"
)

func collectionTrust(t *testing.T) (*fleetadapter.Trust, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(caDER)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "no identity authority"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := fleetadapter.NewTrust(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	if err != nil {
		t.Fatal(err)
	}
	return trust, der
}
func TestPostgresFleetWindowsLostResponseReconciliation(t *testing.T) {
	admin, c := integration(t)
	reset(t, admin)
	repository := runtimeStore(t, admin, c)
	trust, der := collectionTrust(t)
	now := time.Now()
	enrolled := now.Add(-time.Hour).Format(time.RFC3339)
	ctx := context.Background()
	var mu sync.Mutex
	posts := 0
	script := ""
	command := ""
	observedTime := now.Truncate(time.Second).Format(time.RFC3339)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer maintainer" {
			t.Error("credential crossover")
		}
		switch r.URL.Path {
		case "/api/v1/fleet/hosts":
			_ = json.NewEncoder(w).Encode(map[string]any{"hosts": []any{map[string]any{"id": 1, "uuid": "host", "platform": "windows"}}})
		case "/api/v1/fleet/hosts/1":
			_ = json.NewEncoder(w).Encode(map[string]any{"host": map[string]any{"id": 1, "uuid": "host", "platform": "windows", "scripts_enabled": true, "last_enrolled_at": enrolled, "mdm": map[string]any{"enrollment_status": "On (automatic)"}}})
		case "/api/v1/fleet/scripts/run":
			var state string
			if err := admin.pool.QueryRow(ctx, "SELECT state FROM ledger.work WHERE kind LIKE 'fleet-cert:%'").Scan(&state); err != nil || state != "started" {
				t.Errorf("remote mutation preceded durable Start: %s %v", state, err)
			}
			var body struct {
				HostID int    `json:"host_id"`
				Script string `json:"script_contents"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.HostID != 1 {
				t.Error("wrong script target")
			}
			script = body.Script
			parts := strings.Split(script, "# Collection nonce: ")
			command = strings.TrimSpace(parts[len(parts)-1])
			posts++
			// Queue the fake remote script, then lose the response, exercising the real
			// HTTPS client rather than a mocked Coordinator or submission function.
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
		default:
			execution := strings.TrimPrefix(r.URL.Path, "/api/v1/fleet/scripts/results/")
			host := 1
			if execution == "wrong" {
				host = 2
			}
			output, _ := json.Marshal(map[string]any{"version": 1, "certificates": []string{base64.StdEncoding.EncodeToString(der)}})
			_ = json.NewEncoder(w).Encode(map[string]any{"host_id": host, "execution_id": execution, "script_contents": script, "exit_code": 0, "created_at": observedTime, "output": string(output)})
		}
	}))
	defer server.Close()
	client, err := fleetadapter.NewClient(server.URL, "maintainer", server.Client(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	collector := &fleetadapter.Collector{Maintainer: client, Repository: repository, Trust: trust, Now: func() time.Time { return now }}
	batch := domain.DeviceSnapshot{Scope: domain.InventoryScope{ProviderID: "fleet", IDs: []string{"1"}}, Complete: true, ObservedAt: domain.Unix(now), Devices: []domain.Device{{ID: "fleet:1", Identities: []string{"host"}, Groups: []domain.GroupID{}, Enrolled: true}}}
	if err = collector.Prepare(ctx, batch); err != nil {
		t.Fatal(err)
	}
	request := domain.CertificateCollectionRequest{DeviceID: "fleet:1"}
	if _, err = collector.Collect(ctx, request); err == nil {
		t.Fatal("lost submit response accepted")
	}
	for range 3 {
		if _, err = collector.Collect(ctx, request); !errors.Is(err, inventory.ErrPending) {
			t.Fatalf("unknown execution resubmitted %v", err)
		}
	}
	mu.Lock()
	p := posts
	nonce := command
	mu.Unlock()
	if p != 1 {
		t.Fatalf("blind resubmission %d", p)
	}
	var state string
	var attempts int
	_ = admin.pool.QueryRow(ctx, "SELECT state FROM ledger.work").Scan(&state)
	_ = admin.pool.QueryRow(ctx, "SELECT count(*) FROM ledger.attempts").Scan(&attempts)
	if state != "quarantine" || attempts != 1 {
		t.Fatalf("uncertainty not durable %s %d", state, attempts)
	}
	if err = collector.ReconcileWindows(ctx, "fleet:1", nonce, []string{"wrong"}); !errors.Is(err, inventory.ErrPending) {
		t.Fatalf("wrong host reconciled %v", err)
	}
	if err = collector.ReconcileWindows(ctx, "fleet:1", nonce, []string{"one", "two"}); err == nil {
		t.Fatal("ambiguous exact script results reconciled")
	}
	if err = collector.ReconcileWindows(ctx, "fleet:1", nonce, []string{"wrong", "one"}); err != nil {
		t.Fatal(err)
	}
	ob, err := collector.Collect(ctx, request)
	if err != nil || len(ob.Fingerprints) != 1 || !ob.TrustVerified || string(ob.DeviceID) != "fleet:1" {
		t.Fatalf("reconciled observation %+v %v", ob, err)
	}
	original := ob.ObservedAt
	now = now.Add(30 * time.Minute)
	ob, err = collector.Collect(ctx, request)
	if err != nil || ob.ObservedAt != original {
		t.Fatal("cached result observation freshened", err)
	}
	if count(t, admin, "quarantine") != 1 || count(t, admin, "reconciliations") != 1 || count(t, admin, "attempts") != 1 {
		t.Fatal("reconciliation lost attempt/quarantine history")
	}
}
func TestPostgresFleetAppleExactCommandAndPendingBudget(t *testing.T) {
	admin, c := integration(t)
	reset(t, admin)
	repository := runtimeStore(t, admin, c)
	trust, der := collectionTrust(t)
	now := time.Now()
	ctx := context.Background()
	enrolled := now.Add(-time.Hour).Format(time.RFC3339)
	command := ""
	posts := 0
	mode := "pending"
	var mu sync.Mutex
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer maintainer" {
			t.Error("wrong credential")
		}
		switch r.URL.Path {
		case "/api/v1/fleet/hosts":
			_ = json.NewEncoder(w).Encode(map[string]any{"hosts": []any{map[string]any{"id": 1, "uuid": "host", "platform": "darwin"}}})
		case "/api/v1/fleet/hosts/1":
			_ = json.NewEncoder(w).Encode(map[string]any{"host": map[string]any{"id": 1, "uuid": "host", "platform": "darwin", "os_version": "macOS 15.2", "last_mdm_enrolled_at": enrolled, "last_enrolled_at": enrolled, "mdm": map[string]any{"enrollment_status": "On (automatic)"}}})
		case "/api/v1/fleet/commands/run":
			var body struct {
				Command string   `json:"command"`
				Hosts   []string `json:"host_uuids"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.Hosts) != 1 || body.Hosts[0] != "host" {
				t.Error("wrong Apple targets")
			}
			data, _ := base64.StdEncoding.DecodeString(body.Command)
			var parsed struct {
				UUID    string `plist:"CommandUUID"`
				Command struct {
					Type    string `plist:"RequestType"`
					Managed bool   `plist:"ManagedOnly"`
				} `plist:"Command"`
			}
			_, err := plist.Unmarshal(data, &parsed)
			if err != nil || !parsed.Command.Managed || parsed.Command.Type != "CertificateList" {
				t.Error("managed-only command provenance missing")
			}
			command = parsed.UUID
			posts++
			var state string
			_ = admin.pool.QueryRow(ctx, "SELECT state FROM ledger.work WHERE payload->>'command_uuid'=$1", command).Scan(&state)
			if state != "started" {
				t.Error("Apple mutation preceded durable reservation")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"command_uuid": command, "request_type": "CertificateList"})
		case "/api/v1/fleet/commands/results":
			rows := []any{}
			if mode != "pending" {
				data, _ := plist.Marshal(map[string]any{"CommandUUID": command, "UDID": "host", "Status": "Acknowledged", "CertificateList": []any{map[string]any{"IsIdentity": true, "Data": der}}}, plist.BinaryFormat)
				host := "host"
				if mode == "wrong" {
					host = "wrong"
				}
				row := map[string]any{"host_uuid": host, "command_uuid": command, "request_type": "CertificateList", "status": "Acknowledged", "updated_at": now.Truncate(time.Second).Format(time.RFC3339), "result": base64.StdEncoding.EncodeToString(data)}
				rows = append(rows, row)
				if mode == "duplicate" {
					rows = append(rows, row)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": rows})
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	}))
	defer server.Close()
	client, _ := fleetadapter.NewClient(server.URL, "maintainer", server.Client(), time.Second)
	collector := &fleetadapter.Collector{Maintainer: client, Repository: repository, Trust: trust, Now: func() time.Time { return now }}
	batch := domain.DeviceSnapshot{Scope: domain.InventoryScope{ProviderID: "fleet"}, Complete: true, ObservedAt: domain.Unix(now), Devices: []domain.Device{{ID: "fleet:1", Identities: []string{"host"}, Groups: []domain.GroupID{}, Enrolled: true}}}
	if err := collector.Prepare(ctx, batch); err != nil {
		t.Fatal(err)
	}
	request := domain.CertificateCollectionRequest{DeviceID: "fleet:1"}
	for range 3 {
		if _, err := collector.Collect(ctx, request); !errors.Is(err, inventory.ErrPending) {
			t.Fatalf("pending %v", err)
		}
	}
	mu.Lock()
	p := posts
	mode = "wrong"
	mu.Unlock()
	if p != 1 {
		t.Fatalf("pending POST repeated %d", p)
	}
	if _, err := collector.Collect(ctx, request); err == nil {
		t.Fatal("wrong target authorized")
	}
	mu.Lock()
	mode = "duplicate"
	mu.Unlock()
	if _, err := collector.Collect(ctx, request); err == nil {
		t.Fatal("duplicate result authorized")
	}
	mu.Lock()
	mode = "valid"
	mu.Unlock()
	ob, err := collector.Collect(ctx, request)
	if err != nil || len(ob.Fingerprints) != 1 {
		t.Fatalf("valid exact Apple %+v %v", ob, err)
	}
	old := ob.ObservedAt
	now = now.Add(10 * time.Minute)
	ob, err = collector.Collect(ctx, request)
	if err != nil || ob.ObservedAt != old {
		t.Fatalf("repoll freshened Apple %v", err)
	}
	// Trust file contents changing at the same configured path invalidate the
	// old cached observations on the next prepared pass.
	changedTrust, _ := collectionTrust(t)
	collector.ReloadTrust = func() (*fleetadapter.Trust, error) { return changedTrust, nil }
	mu.Lock()
	mode = "pending"
	mu.Unlock()
	if err = collector.Prepare(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if _, err = collector.Collect(ctx, request); !errors.Is(err, inventory.ErrPending) {
		t.Fatalf("trust content change retained old observation %v", err)
	}
	mu.Lock()
	enrolled = now.Add(-time.Minute).Format(time.RFC3339)
	mode = "pending"
	mu.Unlock()
	if _, err = collector.Collect(ctx, request); !errors.Is(err, inventory.ErrPending) {
		t.Fatalf("reenrollment retained old binding %v", err)
	}
}

func TestPostgresFleetFairSelectionSurvivesRestartAndTerminalFailures(t *testing.T) {
	admin, c := integration(t)
	reset(t, admin)
	repository := runtimeStore(t, admin, c)
	trust, _ := collectionTrust(t)
	ctx := context.Background()
	now := time.Now()
	enrolled := now.Add(-time.Hour).Format(time.RFC3339)
	type execution struct {
		host            int
		script, created string
	}
	executions := map[string]execution{}
	submitted := []int{}
	var mu sync.Mutex
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/api/v1/fleet/hosts":
			if token := r.Header.Get("Authorization"); token != "Bearer observer" && token != "Bearer maintainer" {
				t.Error("unexpected credential")
			}
			hosts := []any{}
			for id := 1; id <= 3; id++ {
				hosts = append(hosts, map[string]any{"id": id, "uuid": "host-" + fmt.Sprint(id), "platform": "windows", "team_id": 1, "mdm": map[string]any{"enrollment_status": "On (automatic)"}})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"hosts": hosts})
		case "/api/v1/fleet/scripts/run":
			if r.Header.Get("Authorization") != "Bearer maintainer" {
				t.Error("observer mutated Fleet")
			}
			var body struct {
				HostID int    `json:"host_id"`
				Script string `json:"script_contents"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			nonce := strings.TrimSpace(strings.Split(body.Script, "# Collection nonce: ")[1])
			var state string
			if err := admin.pool.QueryRow(ctx, "SELECT state FROM ledger.work WHERE payload->>'command_uuid'=$1", nonce).Scan(&state); err != nil || state != "started" {
				t.Errorf("missing durable started proof: %s %v", state, err)
			}
			id := "execution-" + fmt.Sprint(len(submitted))
			executions[id] = execution{host: body.HostID, script: body.Script, created: now.Truncate(time.Second).Format(time.RFC3339)}
			submitted = append(submitted, body.HostID)
			_ = json.NewEncoder(w).Encode(map[string]any{"host_id": body.HostID, "execution_id": id})
		default:
			if strings.HasPrefix(r.URL.Path, "/api/v1/fleet/hosts/") {
				id, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/api/v1/fleet/hosts/"))
				if err != nil {
					t.Error(err)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"host": map[string]any{"id": id, "uuid": "host-" + fmt.Sprint(id), "platform": "windows", "scripts_enabled": true, "last_enrolled_at": enrolled, "mdm": map[string]any{"enrollment_status": "On (automatic)"}}})
				return
			}
			id := strings.TrimPrefix(r.URL.Path, "/api/v1/fleet/scripts/results/")
			execution, ok := executions[id]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"host_id": execution.host, "execution_id": id, "script_contents": execution.script, "exit_code": 1, "created_at": execution.created, "output": "authenticated terminal failure"})
		}
	}))
	defer server.Close()
	observerClient, _ := fleetadapter.NewClient(server.URL, "observer", server.Client(), time.Second)
	maintainer, _ := fleetadapter.NewClient(server.URL, "maintainer", server.Client(), time.Second)
	scope := domain.InventoryScope{ProviderID: "fleet"}
	path := filepath.Join(t.TempDir(), "inventory.json")
	// Restart the collector and sync service each pass. There is no volatile cursor
	// capable of explaining progress; original PG reservation ages select work.
	for pass := 0; pass < 5; pass++ {
		collector := &fleetadapter.Collector{Maintainer: maintainer, Repository: repository, Trust: trust, Owner: "worker-" + fmt.Sprint(pass), Options: fleetadapter.CollectionOptions{BatchBudget: 1}, Now: func() time.Time { return now }}
		observer := &fleetadapter.Observer{Client: observerClient, Now: func() time.Time { return now }}
		service := inventoryjob.Service{Provider: observer, Certificates: collector, Scope: scope, Store: new(domain.SnapshotStore), Path: path}
		if err := service.Sync(ctx, false); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		count := len(submitted)
		mu.Unlock()
		if count != pass+1 {
			t.Fatalf("pass budget exceeded or stranded: pass=%d submitted=%d", pass, count)
		}
		// Age only fixture reservations while preserving relative DB age ordering.
		if _, err := admin.pool.Exec(ctx, "UPDATE ledger.work SET created_at=created_at-interval '2 hours'"); err != nil {
			t.Fatal(err)
		}
		now = now.Add(2 * time.Hour)
	}
	mu.Lock()
	actual := append([]int{}, submitted...)
	mu.Unlock()
	if !reflect.DeepEqual(actual, []int{1, 2, 3, 1, 2}) {
		t.Fatalf("later host starved across restarted passes: submissions=%v", actual)
	}
	var unstarted int
	if err := admin.pool.QueryRow(ctx, "SELECT count(*) FROM ledger.attempts WHERE outcome IS NULL").Scan(&unstarted); err != nil || unstarted != 0 {
		t.Fatalf("unfinished actual submission %d %v", unstarted, err)
	}
}
