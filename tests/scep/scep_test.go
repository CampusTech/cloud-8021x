package scep_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/webhook/internal/broker"
	"github.com/CampusTech/cloud-8021x/webhook/internal/challenge"
	"github.com/CampusTech/cloud-8021x/webhook/internal/server"
	"github.com/smallstep/scep"
	"github.com/smallstep/scep/x509util"
)

func must[T any](t *testing.T, value T, err error) T {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func key(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	return must(t, k, err)
}

func certificate(t *testing.T, name string, k *rsa.PrivateKey, parent *x509.Certificate, parentKey *rsa.PrivateKey, ca bool) *x509.Certificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
	if name == "127.0.0.1" {
		template.IPAddresses = []net.IP{net.ParseIP(name)}
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	if ca {
		template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	if parent == nil {
		parent = template
		parentKey = k
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &k.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	return must(t, cert, err)
}
func certPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}
func keyPEM(k *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
}
func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestActualStepCASCEP(t *testing.T) {
	binary := os.Getenv("STEP_CA_BINARY")
	fixturePath := os.Getenv("SCEP_RENDERED_CONFIG")
	if binary == "" || fixturePath == "" {
		t.Skip("run python3 run.py for real step-ca integration")
	}
	t.Run("legacy", func(t *testing.T) { testActualStepCASCEP(t, binary, fixturePath, false) })
	inventoryFixture := os.Getenv("SCEP_INVENTORY_RENDERED_CONFIG")
	if inventoryFixture == "" {
		t.Fatal("missing inventory-mode rendered fixture")
	}
	t.Run("inventory", func(t *testing.T) { testActualStepCASCEP(t, binary, inventoryFixture, true) })
}

func testActualStepCASCEP(t *testing.T, binary, fixturePath string, certificateInventory bool) {
	version, err := exec.Command(binary, "version").CombinedOutput()
	if err != nil || !bytes.Contains(version, []byte("0.30.2")) {
		t.Fatalf("unexpected step-ca binary: %s %v", version, err)
	}
	fixtureBytes, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Config    map[string]any    `json:"config"`
		Templates map[string]string `json:"templates"`
	}
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		t.Fatal(err)
	}
	config := fixture.Config
	provisioner := config["authority"].(map[string]any)["provisioners"].([]any)[0].(map[string]any)
	provisionerName := provisioner["name"].(string)
	options, ok := provisioner["options"].(map[string]any)
	if !ok {
		t.Fatal("actual startup has no provisioner options; hooks would be ignored")
	}
	hooks := options["webhooks"].([]any)
	if len(hooks) != 1 {
		t.Fatal("expected one actual startup challenge hook")
	}
	hook := hooks[0].(map[string]any)
	if !strings.HasPrefix(hook["url"].(string), "https://") {
		t.Fatal("step-ca requires HTTPS webhook URLs")
	}
	if _, ok := hook["secret"]; ok {
		t.Fatal("static webhook secret ignored by pinned step-ca; use mutual TLS")
	}
	if hook["kind"] != "SCEPCHALLENGE" {
		t.Fatal("wrong actual startup hook kind")
	}
	if _, ok := provisioner["challenge"]; ok {
		t.Fatal("actual startup contains shared password bypass")
	}
	const signingKey = "0123456789abcdef0123456789abcdef"
	const byod = "01234567-89ab-cdef-0123-456789abcdef"
	const staff = "STAFF-SERIAL"
	rootKey := key(t)
	root := certificate(t, "Integration root", rootKey, nil, nil, true)
	var enrolled atomic.Bool
	enrolled.Store(true)
	var hookCalls atomic.Int32
	var inventoryMode atomic.Bool
	realHandler := server.NewMutualTLS(signingKey, server.DeciderFunc(func(identity string) bool { return enrolled.Load() && (identity == byod || identity == staff) }))
	inventoryHandler := server.NewMutualTLSInventory(signingKey, provisionerName, server.DeciderFunc(func(identity string) bool { return enrolled.Load() && (identity == byod || identity == staff) }))
	webhook := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hookCalls.Add(1)
		if inventoryMode.Load() {
			inventoryHandler.ServeHTTP(w, r)
		} else {
			realHandler.ServeHTTP(w, r)
		}
	}))
	webhookKey := key(t)
	webhookCert := certificate(t, "127.0.0.1", webhookKey, root, rootKey, false)
	webhookPair, err := tls.X509KeyPair(certPEM(webhookCert), keyPEM(webhookKey))
	if err != nil {
		t.Fatal(err)
	}
	webhookTLS, err := server.ClientTLSConfig(certPEM(root), []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	webhookTLS.Certificates = []tls.Certificate{webhookPair}
	webhook.TLS = webhookTLS
	webhook.StartTLS()
	defer webhook.Close()
	hook["url"] = webhook.URL + "/scep-challenge"
	delete(hook, "secret")
	dir := t.TempDir()
	templatePath := options["x509"].(map[string]any)["templateFile"].(string)
	template, ok := fixture.Templates[templatePath]
	if !ok {
		t.Fatalf("actual startup template missing: %s", templatePath)
	}
	localTemplate := filepath.Join(dir, "wifi-scep.tpl")
	write(t, localTemplate, []byte(template))
	options["x509"].(map[string]any)["templateFile"] = localTemplate
	intermediateKey := key(t)
	intermediate := certificate(t, "Integration intermediate", intermediateKey, root, rootKey, true)
	decrypterKey := key(t)
	decrypter := certificate(t, "Integration SCEP RA", decrypterKey, root, rootKey, false)
	write(t, filepath.Join(dir, "root.pem"), certPEM(root))
	write(t, filepath.Join(dir, "intermediate.pem"), certPEM(intermediate))
	write(t, filepath.Join(dir, "key.pem"), keyPEM(intermediateKey))
	config["root"] = filepath.Join(dir, "root.pem")
	config["crt"] = filepath.Join(dir, "intermediate.pem")
	config["key"] = filepath.Join(dir, "key.pem")
	delete(config, "kms")
	delete(config, "metricsAddress")
	config["dnsNames"] = []string{"localhost", "127.0.0.1"}
	config["db"] = map[string]any{"type": "badgerv2", "dataSource": filepath.Join(dir, "db")}
	provisioner["decrypterCertificate"] = base64.StdEncoding.EncodeToString(certPEM(decrypter))
	provisioner["decrypterKeyPEM"] = base64.StdEncoding.EncodeToString(keyPEM(decrypterKey))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	config["address"] = address
	configBytes, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "ca.json")
	write(t, configPath, configBytes)
	logPath := filepath.Join(dir, "step-ca.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, configPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = logFile.Close()
		if t.Failed() {
			logs, _ := os.ReadFile(logPath)
			t.Logf("step-ca logs:\n%s", logs)
		}
	}()
	roots := x509.NewCertPool()
	roots.AddCert(root)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	base := "https://" + address
	ready := false
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		resp, err := client.Get(base + "/health")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				ready = true
				break
			}
		}
	}
	if !ready {
		t.Fatal("step-ca did not become healthy")
	}
	token, err := challenge.Issue([]byte(signingKey), byod, provisionerName, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	brokerHandler, err := broker.New(broker.Options{Username: "fleet", Token: signingKey, SigningKey: signingKey, SCEPURL: "https://scep.example/scep/" + provisionerName, Provisioner: provisionerName})
	if err != nil {
		t.Fatal(err)
	}
	brokerRequest := httptest.NewRequest("POST", "/fleet/scep-challenge", strings.NewReader(`{"webhook":{"webhookEvent":"SCEPChallenge","id":1,"eventTimestamp":1800000000,"name":"SCEPChallenge"},"event":{"scepServerUrl":"https://scep.example/scep/`+provisionerName+`","payloadIdentifier":"random-fleet-payload-id","payloadTypes":["com.apple.security.scep"]}}`))
	brokerRequest.SetBasicAuth("fleet", signingKey)
	brokerRequest.Header.Set("Content-Type", "application/json")
	brokerResponse := httptest.NewRecorder()
	brokerHandler.ServeHTTP(brokerResponse, brokerRequest)
	if brokerResponse.Code != 200 {
		t.Fatalf("native Fleet broker failed: %d", brokerResponse.Code)
	}
	inventoryToken := brokerResponse.Body.String()
	ndesRequest := httptest.NewRequest("GET", "/fleet/ndes-challenge", nil)
	ndesRequest.SetBasicAuth("fleet", signingKey)
	ndesResponse := httptest.NewRecorder()
	brokerHandler.ServeHTTP(ndesResponse, ndesRequest)
	ndesParts := strings.Split(ndesResponse.Body.String(), "<B> ")
	if ndesResponse.Code != 200 || len(ndesParts) != 2 {
		t.Fatalf("Fleet NDES broker failed: %d", ndesResponse.Code)
	}
	ndesToken := strings.Fields(ndesParts[1])[0]
	clientKey := key(t)
	self := certificate(t, byod, clientKey, nil, nil, false)
	var issued *x509.Certificate
	for _, tc := range []struct {
		name, identity, token string
		messageType           scep.MessageType
		renewSigner, want     bool
		inventory             bool
	}{
		{"bound BYOD issuance and constrained certificate", byod, token, scep.PKCSReq, false, true, false},
		{"enrolled staff impersonation", staff, token, scep.PKCSReq, false, false, false},
		{"shared password", staff, signingKey, scep.PKCSReq, false, false, false},
		{"empty challenge", byod, "", scep.PKCSReq, false, false, false},
		{"renewal with valid token", byod, token, scep.RenewalReq, true, true, false},
		{"renewal without challenge", byod, "", scep.RenewalReq, true, false, false},
		{"renewal staff impersonation", staff, token, scep.RenewalReq, true, false, false},
		{"unenrolled device", byod, token, scep.PKCSReq, false, false, false},
		{"inventory challenge rejected when mode disabled", staff, inventoryToken, scep.PKCSReq, false, false, false},
		{"NDES challenge rejected when mode disabled", staff, ndesToken, scep.PKCSReq, false, false, false},
		{"inventory neutral issuance ignores claimed staff CN and enrollment", staff, inventoryToken, scep.PKCSReq, false, true, true},
		{"inventory challenge retry with different claimed CN", "attacker-selected", inventoryToken, scep.PKCSReq, false, true, true},
		{"inventory renewal preserves neutral subject", staff, inventoryToken, scep.RenewalReq, true, true, true},
		{"inventory renewal without challenge", staff, "", scep.RenewalReq, true, false, true},
		{"inventory shared signing key rejected", staff, signingKey, scep.PKCSReq, false, false, true},
		{"Windows NDES neutral issuance", staff, ndesToken, scep.PKCSReq, false, true, true},
		{"Windows NDES renewal", staff, ndesToken, scep.RenewalReq, true, true, true},
	} {
		if tc.inventory != certificateInventory {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			if certificateInventory {
				enrolled.Store(false)
			}
			inventoryMode.Store(tc.inventory)
			if tc.name == "unenrolled device" {
				enrolled.Store(false)
			}
			signer := self
			if tc.renewSigner {
				if issued == nil {
					t.Fatal("missing previously issued certificate")
				}
				signer = issued
			}
			csrDER, err := x509util.CreateCertificateRequest(rand.Reader, &x509util.CertificateRequest{CertificateRequest: x509.CertificateRequest{Subject: pkix.Name{CommonName: tc.identity, OrganizationalUnit: []string{"renewal-id"}}, DNSNames: []string{"radius.example.com"}}, ChallengePassword: tc.token}, clientKey)
			if err != nil {
				t.Fatal(err)
			}
			csr, err := x509.ParseCertificateRequest(csrDER)
			if err != nil {
				t.Fatal(err)
			}
			message, err := scep.NewCSRRequest(csr, &scep.PKIMessage{MessageType: tc.messageType, Recipients: []*x509.Certificate{decrypter}, SignerCert: signer, SignerKey: clientKey})
			if err != nil {
				t.Fatal(err)
			}
			before := hookCalls.Load()
			resp, err := client.Post(base+"/scep/"+provisionerName+"?operation=PKIOperation", "application/x-pki-message", bytes.NewReader(message.Raw))
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if hookCalls.Load() != before+1 {
				t.Fatalf("request did not reach configured real webhook; status=%d body=%s", resp.StatusCode, body)
			}
			if resp.StatusCode != 200 {
				t.Fatalf("expected SCEP CertRep, status=%d body=%s", resp.StatusCode, body)
			}
			reply, err := scep.ParsePKIMessage(body, scep.WithCACerts([]*x509.Certificate{decrypter, intermediate, root}))
			if err != nil {
				t.Fatal(err)
			}
			if !tc.want {
				if reply.PKIStatus != scep.FAILURE {
					t.Fatalf("unauthorized SCEP request returned %s", reply.PKIStatus)
				}
				return
			}
			if reply.PKIStatus != scep.SUCCESS {
				t.Fatalf("authorized SCEP request denied: %s", reply.FailInfo)
			}
			if err := reply.DecryptPKIEnvelope(signer, clientKey); err != nil {
				t.Fatal(err)
			}
			cert := reply.Certificate
			expectedCN := tc.identity
			if certificateInventory {
				expectedCN = "cloud-8021x-inventory"
			}
			if cert.Subject.CommonName != expectedCN {
				t.Fatalf("wrong issued identity: %s", cert.Subject.CommonName)
			}
			if len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 || len(cert.URIs) != 0 || len(cert.EmailAddresses) != 0 {
				t.Fatal("attacker CSR SAN copied into client certificate")
			}
			if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
				t.Fatalf("unexpected EKU: %v", cert.ExtKeyUsage)
			}
			if strings.Join(cert.Subject.OrganizationalUnit, ",") != "renewal-id" {
				t.Fatal("renewal OU lost")
			}
			intermediates := x509.NewCertPool()
			intermediates.AddCert(intermediate)
			if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
				t.Fatal(err)
			}
			issued = cert
		})
	}
}
