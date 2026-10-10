package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
	"github.com/CampusTech/cloud-8021x/internal/adapters/freeradius/native"
	radiuspolicy "github.com/CampusTech/cloud-8021x/internal/adapters/freeradius/policy"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/identity"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/sirupsen/logrus"
)

// This fixture uses the exact production constructor, local TLS providers and a
// real isolated PG16 ledger. The proxy's cut closes established PG connections;
// it does not fake SQL results. Native/systemd packet acceptance is separate.
func TestInstalledAssembledDaemonLedgerOutageAndCancellation(t *testing.T) {
	if os.Getenv("C8021X_DAEMON_FIXTURE") != "task9" {
		t.Skip("owned Linux PG daemon fixture required")
	}
	ctx := context.Background()
	write := func(path string, data []byte, mode os.FileMode) {
		t.Helper()
		if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(path, data, mode); e != nil {
			t.Fatal(e)
		}
	}
	for _, class := range []string{"accounting", "export", "auth", "certificates", "observation"} {
		write(filepath.Join(postgres.RuntimePoolDirectory, class+".lock"), nil, 0600)
	}
	cfg := configuredFixture(t)
	cfg.InstanceID = "radius-primary"
	cfg.Hostname = "radius-primary"
	cfg.StateTransition = strings.Repeat("a", 64)
	cfg.Bootstrap.LocalAddress = "127.0.0.1"
	cfg.Bootstrap.PeerAddress = "127.0.0.2"
	cfg.Bootstrap.ServerDNS = "radius.fixture"
	cfg.Bootstrap.HealthSecret.File = "/run/daemon-fixture/health"
	cfg.Listeners.Policy.Address = "127.0.0.1:19080"
	cfg.Listeners.HealthAddress = "127.0.0.1:19082"
	cfg.Listeners.MetricsAddress = "127.0.0.1:19083"
	cfg.Policy.InventoryMaxAge = 5 * time.Second
	cfg.Database.CAFile = os.Getenv("C8021X_PG_TEST_CA")
	cfg.Database.ConnectTimeout = time.Second
	cfg.Database.QueryTimeout = time.Second
	cfg.Paths.HandoffDir = "/run/daemon-fixture/handoffs"
	cfg.Schedules.Metrics = time.Second
	cfg.Inventory.Enabled = true
	cfg.Inventory.Fleet.ObserverToken.File = "/run/daemon-fixture/observer"
	cfg.Inventory.Fleet.ManagedCertificates = false
	var fleetCalls, networkCalls, telemetryCalls atomic.Int32
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("unexpected provider mutation")
			w.WriteHeader(405)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/fleet/") {
			fleetCalls.Add(1)
			if r.Header.Get("Authorization") != "Bearer observer" {
				t.Error("wrong observer credential")
			}
			w.WriteHeader(503)
			return
		}
		networkCalls.Add(1)
		if r.Header.Get("X-API-Key") != "unifi" {
			t.Error("wrong network credential")
		}
		if strings.HasSuffix(r.URL.Path, "/sites") {
			_, _ = io.WriteString(w, `{"data":[{"id":"office","name":"Office"}],"offset":0,"count":1,"totalCount":1}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":[],"offset":0,"count":0,"totalCount":0}`)
	}))
	defer provider.Close()
	providerCA := "/run/daemon-fixture/provider-ca.pem"
	write(providerCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.Certificate().Raw}), 0644)
	t.Setenv("SSL_CERT_FILE", providerCA)
	t.Setenv("SSL_CERT_DIR", "/run/daemon-fixture/no-extra-trust")
	cfg.Inventory.Fleet.BaseURL = provider.URL
	cfg.Network.Providers = []config.NetworkProvider{{ID: "unifi", Kind: "unifi", BaseURL: provider.URL, ConsoleID: "console", Scopes: []string{"office"}, Credential: config.SecretRef{File: "/run/daemon-fixture/unifi"}, Timeout: time.Second}}
	cfg.Network.Locations = []config.Location{{ID: "office", ProviderID: "unifi", SiteID: "office", VLANEnabled: true}}
	cfg.RadiusClients = []config.RadiusClient{{ID: "ap", LocationID: "office", CIDRs: []string{"192.0.2.0/24"}, Medium: "wifi", SignalingProfile: "unifi-numeric", Secret: config.SecretRef{File: "/run/daemon-fixture/radius-secret"}}}
	cfg.Policy.Rules = []config.VLANRule{{GroupID: "fleet:1", LocationID: "office", VLAN: 120}}
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		telemetryCalls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(200)
	}))
	defer collector.Close()
	cfg.Telemetry.Enabled = true
	cfg.Telemetry.Logs = true
	cfg.Telemetry.Traces = true
	cfg.Telemetry.Metrics = true
	cfg.Telemetry.Endpoint = collector.URL
	cfg.Telemetry.BusinessEndpoint = collector.URL
	cfg.Telemetry.Timeout = time.Second
	cfg.Telemetry.ShutdownTimeout = 2 * time.Second
	cfg.Telemetry.TraceSampleRatio = 1
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	leafKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "fixture-client"}, DNSNames: []string{"radius.fixture", "client.fixture"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyDER, e := x509.MarshalPKCS8PrivateKey(leafKey)
	if e != nil {
		t.Fatal(e)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	write("/etc/cloud-8021x/client-cas.pem", caPEM, 0644)
	write("/etc/cloud-8021x/radius-server.pem", leafPEM, 0644)
	write("/run/daemon-fixture/webhook-key", keyPEM, 0600)
	cfg.Listeners.Webhook = config.TLSListener{Enabled: true, Address: "127.0.0.1:19444", CertFile: "/etc/cloud-8021x/radius-server.pem", KeyFile: config.SecretRef{File: "/run/daemon-fixture/webhook-key"}, ClientCAFiles: []string{"/etc/cloud-8021x/client-cas.pem"}, ClientDNSNames: []string{"client.fixture"}}
	for p, v := range map[string]string{cfg.Policy.ClassSigningKey.File: strings.Repeat("k", 32), cfg.Listeners.Policy.Token.File: strings.Repeat("p", 32), cfg.Bootstrap.HealthSecret.File: strings.Repeat("h", 32), cfg.Inventory.Fleet.ObserverToken.File: "observer", cfg.Network.Providers[0].Credential.File: "unifi"} {
		write(p, []byte(v), 0600)
	}
	sum := sha256.Sum256(leafDER)
	fingerprint := hex.EncodeToString(sum[:])
	fps := []string{fingerprint}
	snapshot, e := domain.BuildSnapshot([]domain.Device{{ID: "fleet:1", Identities: []string{"fixture-uuid"}, Enrolled: true, Groups: []domain.GroupID{"fleet:1"}, Fingerprints: &fps, CertificatesObservedAt: domain.Unix(now)}}, domain.Unix(now))
	if e != nil {
		t.Fatal(e)
	}
	policyRaw, e := json.Marshal(snapshot)
	if e != nil {
		t.Fatal(e)
	}
	write(cfg.Paths.InventoryFile, policyRaw, 0644)
	nativeAccount, e := user.Lookup("freerad")
	if e != nil {
		t.Fatal(e)
	}
	nativeUID, _ := strconv.Atoi(nativeAccount.Uid)
	eventGroup, e := user.LookupGroup("cloud8021x-events")
	if e != nil {
		t.Fatal(e)
	}
	eventGID, _ := strconv.Atoi(eventGroup.Gid)
	if e = os.MkdirAll(cfg.Paths.AuthLogDir, 0750); e != nil {
		t.Fatal(e)
	}
	if e = os.Chown(cfg.Paths.AuthLogDir, nativeUID, eventGID); e != nil {
		t.Fatal(e)
	}
	authPath := filepath.Join(cfg.Paths.AuthLogDir, "auth-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-2026100810.detail")
	authRaw := []byte(fmt.Sprintf("fixture\n\tPacket-Type = Access-Accept\n\tC8021X-Receipt = %d\n\tC8021X-Client = \"ap\"\n\tC8021X-Location = \"office\"\n\n", now.Unix()))
	write(authPath, authRaw, 0640)
	if e = os.Chown(authPath, nativeUID, eventGID); e != nil {
		t.Fatal(e)
	}
	adminDSN := os.Getenv("C8021X_PG_TEST_DSN")
	admin, e := postgres.NewMigration(ctx, adminDSN, cfg.Database)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Close()
	if e = admin.Migrate(ctx, postgres.Roles{Runtime: "app_runtime", Native: "app_native"}); e != nil {
		t.Fatal(e)
	}
	gate := postgres.MaintenanceGate{Store: admin}
	digest := strings.Repeat("b", 64)
	for _, node := range []string{"radius-primary", "radius-secondary"} {
		if e = gate.With(ctx, "fixture-fence", func(ctx context.Context) error {
			return admin.RecordWriterFence(ctx, cfg.StateTransition, node, digest, digest)
		}); e != nil {
			t.Fatal(e)
		}
	}
	// Signed source handoff is covered by its dedicated integration suite.
	// This owned fixture seeds worker authority to test the assembled daemon's
	// behavior during a real database outage.
	fixtureAdmin, e := pgx.Connect(ctx, adminDSN)
	if e != nil {
		t.Fatal(e)
	}
	_, e = fixtureAdmin.Exec(ctx, "UPDATE bootstrap_private.transitions SET enabled=true WHERE id=$1", cfg.StateTransition)
	_ = fixtureAdmin.Close(ctx)
	if e != nil {
		t.Fatal(e)
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = listener.Close() }()
	var cut atomic.Bool
	var mu sync.Mutex
	connections := []net.Conn{}
	go func() {
		for {
			client, e := listener.Accept()
			if e != nil {
				return
			}
			if cut.Load() {
				_ = client.Close()
				continue
			}
			server, e := net.DialTimeout("tcp", "127.0.0.1:5432", time.Second)
			if e != nil {
				_ = client.Close()
				continue
			}
			mu.Lock()
			connections = append(connections, client, server)
			mu.Unlock()
			go func() { _, _ = io.Copy(server, client); _ = server.Close() }()
			go func() { _, _ = io.Copy(client, server); _ = client.Close() }()
		}
	}()
	outage := func() {
		cut.Store(true)
		mu.Lock()
		defer mu.Unlock()
		for _, c := range connections {
			_ = c.Close()
		}
	}
	defer outage()
	runtimeDSN, _ := url.Parse(adminDSN)
	runtimeDSN.User = url.UserPassword("app_runtime", "disposable-runtime")
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	runtimeDSN.Host = net.JoinHostPort("localhost", port)
	write(cfg.Database.RuntimeDSN.File, []byte(runtimeDSN.String()), 0600)
	if e = cfg.Validate(); e != nil {
		t.Fatal(e)
	}
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	daemon, closeDaemon, e := buildDaemon(ctx, cfg, RunOptions{Logger: logger, Version: "task9-fixture"})
	if e != nil {
		t.Fatal(e)
	}
	defer closeDaemon()
	ready := make(chan struct{}, 1)
	stopping := make(chan struct{}, 1)
	daemon.Notify = func(s string) error {
		if s == "READY=1" {
			ready <- struct{}{}
		}
		if s == "STOPPING=1" {
			stopping <- struct{}{}
		}
		return nil
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- daemon.Run(runCtx) }()
	select {
	case <-ready:
	case e := <-done:
		t.Fatal("constructor lifecycle failed", e)
	case <-time.After(4 * time.Second):
		t.Fatal("private READY absent")
	}
	expected, e := native.ExpectedReadiness(cfg, caPEM)
	if e != nil {
		t.Fatal(e)
	}
	if e = native.ProbeReadiness(ctx, "http://127.0.0.1:18122", []byte(strings.Repeat("h", 32)), expected); e != nil {
		t.Fatal(e)
	}
	if e = native.ProbeReadiness(ctx, "http://127.0.0.1:18122", []byte(strings.Repeat("x", 32)), expected); e == nil {
		t.Fatal("foreign peer secret accepted")
	}
	requestPolicy := func(want int, seq byte) {
		t.Helper()
		token := strings.Repeat(string(seq), 64)
		handoff := identity.Handoff{Directory: cfg.Paths.HandoffDir, MaxAge: cfg.Policy.HandoffMaxAge}
		if e := handoff.RecordPEM(leafPEM, token, nil, time.Now()); e != nil {
			t.Fatal(e)
		}
		raw, _ := json.Marshal(radiuspolicy.Request{Server: radiuspolicy.ServerContext{ClientID: "ap", SourceIP: "192.0.2.10"}, HandoffTokens: []string{token}, CallingStations: []string{"aa:bb:cc:dd:ee:ff"}, NASPortTypes: []string{"19"}})
		req, _ := http.NewRequest("POST", "http://"+cfg.Listeners.Policy.Address+"/authorize", bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+strings.Repeat("p", 32))
		req.Header.Set("Content-Type", "application/json")
		res, e := (&http.Client{Timeout: time.Second}).Do(req)
		if e != nil {
			t.Fatal(e)
		}
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if res.StatusCode != want {
			t.Fatalf("policy=%d want=%d body=%s", res.StatusCode, want, body)
		}
		if want == 200 {
			var attrs map[string]radiuspolicy.RESTAttribute
			if json.Unmarshal(body, &attrs) != nil {
				t.Fatal("bad policy result")
			}
			if fmt.Sprint(attrs["reply:Tunnel-Type"].Value) != "[13]" || fmt.Sprint(attrs["reply:Tunnel-Medium-Type"].Value) != "[6]" || fmt.Sprint(attrs["reply:Tunnel-Private-Group-Id"].Value) != "[120]" {
				t.Fatal("VLAN parity", string(body))
			}
			value, ok := attrs["reply:Class"].Value[0].(string)
			if !ok || binding.Verify([]byte(strings.Repeat("k", 32)), []string{value}, "office", []string{"aa:bb:cc:dd:ee:ff"}, time.Now(), cfg.Policy.ClassMaxAge) == nil {
				t.Fatal("Class parity")
			}
		}
	}
	requestPolicy(200, 'a')
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	pair, e := tls.X509KeyPair(leafPEM, keyPEM)
	if e != nil {
		t.Fatal(e)
	}
	authenticated := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{pair}}}}
	response, e := authenticated.Get("https://" + cfg.Listeners.Webhook.Address + "/healthz")
	if e != nil {
		t.Fatal(e)
	}
	_ = response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("webhook health", response.StatusCode)
	}
	databaseConfig, e := pgx.ParseConfig(adminDSN)
	if e != nil {
		t.Fatal(e)
	}
	pgCA, e := os.ReadFile(cfg.Database.CAFile)
	if e != nil {
		t.Fatal(e)
	}
	pgRoots := x509.NewCertPool()
	pgRoots.AppendCertsFromPEM(pgCA)
	databaseConfig.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pgRoots, ServerName: "localhost"}
	databaseConfig.Fallbacks = nil
	inspect, e := pgx.ConnectConfig(ctx, databaseConfig)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = inspect.Close(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var succeeded int
		e = inspect.QueryRow(ctx, "SELECT count(*) FROM ledger.work WHERE kind='outbox' AND state='succeeded'").Scan(&succeeded)
		if e != nil {
			t.Fatal(e)
		}
		if succeeded > 0 && fleetCalls.Load() > 0 && networkCalls.Load() >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("assembled jobs did not progress: work=%d fleet=%d network=%d", succeeded, fleetCalls.Load(), networkCalls.Load())
		}
		time.Sleep(20 * time.Millisecond)
	}
	outage()
	requestPolicy(200, 'b')
	file, e := os.OpenFile(authPath, os.O_APPEND|os.O_WRONLY, 0)
	if e != nil {
		t.Fatal(e)
	}
	_, e = file.Write(authRaw)
	_ = file.Close()
	if e != nil {
		t.Fatal(e)
	}
	time.Sleep(time.Until(now.Add(6 * time.Second)))
	requestPolicy(403, 'c')
	if e = native.ProbeReadiness(ctx, "http://127.0.0.1:18122", []byte(strings.Repeat("h", 32)), expected); e == nil {
		t.Fatal("stale private readiness remained true")
	}
	var cursor string
	if e = inspect.QueryRow(ctx, "SELECT cursor FROM ledger.auth_cursors LIMIT 1").Scan(&cursor); e != nil || cursor != strconv.Itoa(len(authRaw)) {
		t.Fatal("database outage advanced native cursor", cursor, e)
	}
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("assembled cancellation exceeded bound")
	}
	select {
	case <-stopping:
	default:
		t.Fatal("missing stopping notification")
	}
	if telemetryCalls.Load() == 0 {
		t.Fatal("OTel/export flush never reached bounded local collector")
	}
	for _, address := range []string{cfg.Listeners.Policy.Address, cfg.Listeners.Webhook.Address, "127.0.0.1:18122", cfg.Listeners.HealthAddress, cfg.Listeners.MetricsAddress} {
		c, e := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if e == nil {
			_ = c.Close()
			t.Fatal("listener survived cancellation", address)
		}
	}
}
