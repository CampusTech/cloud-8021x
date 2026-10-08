package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"

	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
	"github.com/CampusTech/cloud-8021x/internal/adapters/network/signaling"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/identity"
	core "github.com/CampusTech/cloud-8021x/internal/policy"
)

func setup(t *testing.T) (*LocalService, Request, identity.Handoff) {
	t.Helper()
	now := time.Now()
	h := identity.Handoff{Directory: filepath.Join(t.TempDir(), "handoff"), MaxAge: 120 * time.Second}
	p := filepath.Join(t.TempDir(), "leaf")
	_ = os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("verified leaf")}), 0600)
	token := strings.Repeat("a", 64)
	if err := h.Record(p, token, nil, now); err != nil {
		t.Fatal(err)
	}
	// Independently calculate exact leaf fingerprint without creating an authorization input.
	fp := "9c433031f467496e21d3f22c9a7dc7f70c2c44ec2a8e399d2543e131e7cc8d10"
	fps := []string{fp}
	s, err := domain.BuildSnapshot([]domain.Device{{ID: "other:1", Identities: []string{"SERIAL"}, Groups: []domain.GroupID{"other:staff"}, Enrolled: true, Fingerprints: &fps, CertificatesObservedAt: domain.Unix(now)}}, domain.Unix(now))
	if err != nil {
		t.Fatal(err)
	}
	store := new(domain.SnapshotStore)
	if err := store.Set(s); err != nil {
		t.Fatal(err)
	}
	e, err := core.New(core.Config{IdentityMode: core.FingerprintMode, InventoryMaxAge: time.Hour, CertificateMaxAge: time.Hour, Locations: []core.Location{{ID: "nyc", VLANEnabled: true}, {ID: "sac", VLANEnabled: false}}, Rules: []core.Rule{{GroupID: "other:staff", LocationID: "nyc", VLAN: 120}}})
	if err != nil {
		t.Fatal(err)
	}
	trust, err := core.NewTrustMap([]core.Client{{ID: "ap", LocationID: "nyc", CIDRs: []string{"192.0.2.0/24"}, Medium: domain.WiFi, SignalingProfile: "unifi-numeric"}, {ID: "sac", LocationID: "sac", CIDRs: []string{"198.51.100.1/32"}, Medium: domain.WiFi, SignalingProfile: "meraki-numeric"}})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signaling.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewLocalService(ServiceOptions{Engine: e, Snapshots: store, Trust: trust, Handoff: h, Signaling: sig, ClassKey: bytes.Repeat([]byte("A"), 64)})
	if err != nil {
		t.Fatal(err)
	}
	return service, Request{NASPortTypes: []string{"19"}, Server: ServerContext{ClientID: "ap", SourceIP: "192.0.2.19"}, HandoffTokens: []string{token}, CallingStations: []string{"AA-BB-CC-DD-EE-FF"}}, h
}
func request(t *testing.T, h http.Handler, body []byte, token, remote string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", "http://localhost/authorize", bytes.NewReader(body))
	r.RemoteAddr = remote
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func handler(t *testing.T, s DecisionService) http.Handler {
	t.Helper()
	h, err := NewHandler(HTTPOptions{Token: bytes.Repeat([]byte("k"), 32), MaxConcurrency: 1, MaxBodyBytes: 4096, Timeout: 50 * time.Millisecond, Service: s})
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func TestLocalRESTExactVLANClassSingleUseAndTrustedContext(t *testing.T) {
	s, r, handoff := setup(t)
	h := handler(t, s)
	raw, _ := json.Marshal(r)
	w := request(t, h, raw, strings.Repeat("k", 32), "127.0.0.1:10")
	if w.Code != 200 {
		t.Fatalf("accept %d %s", w.Code, w.Body.String())
	}
	var reply RESTReply
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if reply["reply:Tunnel-Type"].Value[0].(float64) != 13 || reply["reply:Tunnel-Medium-Type"].Value[0].(float64) != 6 || reply["reply:Tunnel-Private-Group-Id"].Value[0] != "120" {
		t.Fatal(reply)
	}
	token := reply["reply:Class"].Value[0].(string)
	if binding.Verify(bytes.Repeat([]byte("A"), 64), []string{token}, "nyc", r.CallingStations, time.Now(), binding.MaxAge) == nil {
		t.Fatal("unsigned Class")
	}
	if request(t, h, raw, strings.Repeat("k", 32), "127.0.0.1:10").Code != 403 {
		t.Fatal("handoff replay")
	}
	_ = handoff
}
func TestOptOutKeepsClassAndExactChecks(t *testing.T) {
	s, r, _ := setup(t)
	r.Server = ServerContext{ClientID: "sac", SourceIP: "198.51.100.1"}
	raw, _ := json.Marshal(r)
	w := request(t, handler(t, s), raw, strings.Repeat("k", 32), "127.0.0.1:10")
	var reply RESTReply
	_ = json.Unmarshal(w.Body.Bytes(), &reply)
	if w.Code != 200 || len(reply) != 1 || len(reply["reply:Class"].Value) != 1 {
		t.Fatal("optout", w.Code, reply)
	}
}
func TestRESTRejectsSpoofedAndDuplicateInputs(t *testing.T) {
	for _, kind := range []string{"wrong-token", "remote", "spoof-source", "missing-station", "duplicate-station", "duplicate-handoff", "fingerprint", "site", "duplicate-json", "oversize", "wrong-content-type"} {
		t.Run(kind, func(t *testing.T) {
			s, r, _ := setup(t)
			token := strings.Repeat("k", 32)
			remote := "127.0.0.1:10"
			switch kind {
			case "wrong-token":
				token = strings.Repeat("x", 32)
			case "remote":
				remote = "192.0.2.1:10"
			case "spoof-source":
				r.Server.SourceIP = "198.51.100.1"
			case "missing-station":
				r.CallingStations = nil
			case "duplicate-station":
				r.CallingStations = append(r.CallingStations, r.CallingStations[0])
			case "duplicate-handoff":
				r.HandoffTokens = append(r.HandoffTokens, r.HandoffTokens[0])
			}
			raw, _ := json.Marshal(r)
			switch kind {
			case "fingerprint":
				raw = []byte(`{"fingerprint":"` + strings.Repeat("a1", 32) + `"}`)
			case "site":
				raw = []byte(`{"site":"sac"}`)
			case "duplicate-json":
				raw = []byte(`{"server":{"client_id":"ap","client_id":"ap","source_ip":"192.0.2.1"}}`)
			case "oversize":
				raw = bytes.Repeat([]byte("a"), 4097)
			}
			w := request(t, handler(t, s), raw, token, remote)
			if kind == "wrong-content-type" {
				q := httptest.NewRequest("POST", "http://localhost/authorize", bytes.NewReader(raw))
				q.RemoteAddr = remote
				q.Header.Set("Authorization", "Bearer "+token)
				w = httptest.NewRecorder()
				handler(t, s).ServeHTTP(w, q)
			}
			if w.Code == 200 {
				t.Fatalf("accepted %s", kind)
			}
		})
	}
}

type blockedService struct{ entered chan struct{} }

func (s blockedService) Decide(ctx context.Context, _ Request) (Result, error) {
	s.entered <- struct{}{}
	<-ctx.Done()
	return Result{}, ctx.Err()
}
func TestRESTBoundsDeadlineConcurrencyAndNoAccountingRoute(t *testing.T) {
	s := blockedService{entered: make(chan struct{}, 1)}
	h := handler(t, s)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- request(t, h, []byte(`{"server":{}}`), strings.Repeat("k", 32), "127.0.0.1:10") }()
	<-s.entered
	w := request(t, h, []byte(`{}`), strings.Repeat("k", 32), "127.0.0.1:11")
	if w.Code != 503 {
		t.Fatal("overload", w.Code)
	}
	select {
	case w = <-done:
		if w.Code != 503 {
			t.Fatal("deadline", w.Code)
		}
	case <-time.After(time.Second):
		t.Fatal("unbounded deadline")
	}
	r := httptest.NewRequest("POST", "http://localhost/accounting", strings.NewReader(`{}`))
	r.RemoteAddr = "127.0.0.1:10"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatal("accounting callback exposed")
	}
}
func TestRESTConstructionBounds(t *testing.T) {
	for _, o := range []HTTPOptions{{}, {Token: []byte("short"), MaxConcurrency: 1, MaxBodyBytes: 1, Timeout: time.Second}, {Token: bytes.Repeat([]byte("k"), 32), MaxConcurrency: 0, MaxBodyBytes: 1, Timeout: time.Second}, {Token: bytes.Repeat([]byte("k"), 32), MaxConcurrency: 1, MaxBodyBytes: 1<<20 + 1, Timeout: time.Second}} {
		if _, err := NewHandler(o); err == nil {
			t.Fatal("invalid options")
		}
	}
}

type ignoresContext struct {
	started chan struct{}
	release chan struct{}
}

func (s ignoresContext) Decide(context.Context, Request) (Result, error) {
	s.started <- struct{}{}
	<-s.release
	return Result{}, nil
}
func TestDeadlineReturnsEvenIfCapabilityIgnoresCancellationAndKeepsSlotBounded(t *testing.T) {
	s := ignoresContext{started: make(chan struct{}, 1), release: make(chan struct{})}
	h := handler(t, s)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- request(t, h, []byte(`{}`), strings.Repeat("k", 32), "127.0.0.1:10") }()
	<-s.started
	select {
	case w := <-done:
		if w.Code != 503 {
			t.Fatal("deadline", w.Code)
		}
	case <-time.After(300 * time.Millisecond):
		close(s.release)
		t.Fatal("handler exceeded deadline")
	}
	if w := request(t, h, []byte(`{}`), strings.Repeat("k", 32), "127.0.0.1:11"); w.Code != 503 {
		t.Fatal("slot was released while capability is still running", w.Code)
	}
	close(s.release)
}
func TestNativeAttributionPreservesDuplicateCountsAndReceipt(t *testing.T) {
	key := bytes.Repeat([]byte("A"), 64)
	receipt := time.Unix(1700000000, 0)
	token, err := binding.Issue(key, binding.Attribution{DeviceID: "other:1", Fingerprint: strings.Repeat("a1", 32)}, "nyc", "AABBCCDDEEFF", receipt)
	if err != nil {
		t.Fatal(err)
	}
	i := AttributionInput{Classes: []string{token}, ClassCount: 1, Stations: []string{"AABBCCDDEEFF"}, StationCount: 1, LocationID: "nyc", Receipt: receipt.Add(time.Second)}
	if VerifyAttribution(key, i, binding.MaxAge) == nil {
		t.Fatal("valid original receipt")
	}
	i.ClassCount = 2
	if VerifyAttribution(key, i, binding.MaxAge) != nil {
		t.Fatal("duplicate Class collapsed")
	}
	i.ClassCount = 1
	i.StationCount = 2
	if VerifyAttribution(key, i, binding.MaxAge) != nil {
		t.Fatal("duplicate station collapsed")
	}
}
func TestPolicyFromConfigUsesOnlyLocalSnapshotsAndProtectedTokens(t *testing.T) {
	data, err := os.ReadFile("../../../../examples/cloud-8021x.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg.Paths.InventoryFile = filepath.Join(dir, "inventory")
	cfg.Paths.DowngradeGuardFile = filepath.Join(dir, "guard")
	cfg.Listeners.Policy.Token.File = filepath.Join(dir, "token")
	cfg.Policy.ClassSigningKey.File = filepath.Join(dir, "key")
	cfg.Paths.HandoffDir = filepath.Join(dir, "handoff")
	s, r, h := setup(t)
	cfg.RadiusClients[0].ID = r.Server.ClientID
	cfg.RadiusClients[0].CIDRs = []string{"192.0.2.0/24"}
	cfg.RadiusClients[1].CIDRs = []string{"198.51.100.1/32"}
	cfg.Policy.Rules[0].GroupID = "other:staff"
	cfg.Paths.HandoffDir = h.Directory
	if err := domain.PublishSnapshotFile(cfg.Paths.InventoryFile, s.Snapshots().Load()); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(cfg.Listeners.Policy.Token.File, bytes.Repeat([]byte("k"), 32), 0600)
	_ = os.WriteFile(cfg.Policy.ClassSigningKey.File, bytes.Repeat([]byte("A"), 64), 0600)
	local, handler, err := FromConfig(cfg, nil)
	if err != nil || local == nil || handler == nil {
		t.Fatal("local construction", err)
	}
	raw, _ := json.Marshal(r)
	if w := request(t, handler, raw, strings.Repeat("k", 32), "127.0.0.1:10"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cfg.Policy.IdentityMode = "legacy-serial"
	if _, _, err := FromConfig(cfg, nil); err == nil {
		t.Fatal("sticky downgrade bypass")
	}
	cfg.Policy.IdentityMode = "fingerprint"
	_ = os.Chmod(cfg.Listeners.Policy.Token.File, 0644)
	if _, _, err := FromConfig(cfg, nil); err == nil {
		t.Fatal("public bearer token file accepted")
	}
}
