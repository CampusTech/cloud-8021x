package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testTLSCertificate(t *testing.T, name string, dns []string, usage []x509.ExtKeyUsage, ca bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (tls.Certificate, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: dns, ExtKeyUsage: usage, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: ca, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	if ca {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	if parent == nil {
		parent = template
		parentKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}, cert, key
}

func TestMutualTLSRejectsUnsignedTransport(t *testing.T) {
	h := NewMutualTLS(challengeKey, DeciderFunc(func(string) bool { return true }))
	token := issueChallenge(t, "device", time.Now())
	for _, tc := range []struct {
		name, path, body string
		tlsState         *tls.ConnectionState
	}{
		{"plain HTTP", "/scep-challenge", scepBody(t, "device", token, "wifi-scep"), nil},
		{"unverified certificate", "/scep-challenge", scepBody(t, "device", token, "wifi-scep"), &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}},
		{"ACME plain HTTP", "/authorize", `{"attestationData":{"permanentIdentifier":"device"}}`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
			r.TLS = tc.tlsState
			r.Header.Set("X-Smallstep-Signature", sigOf("", tc.body))
			r.Header.Set("X-Forwarded-Client-Cert", "trusted")
			r.Header.Set("X-SSL-Client-Verify", "SUCCESS")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			var result ResponseShape
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Allow {
				t.Fatal("request authenticated without a verified TLS client chain")
			}
		})
	}
}

func TestClientTLSConfigurationAndRealHandshake(t *testing.T) {
	_, root, rootKey := testTLSCertificate(t, "root", nil, nil, true, nil, nil)
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
	for _, tc := range []struct {
		name  string
		roots []byte
		names []string
	}{
		{"no roots", nil, []string{"ca.example.test"}},
		{"malformed roots", []byte("bad"), []string{"ca.example.test"}},
		{"no names", rootPEM, nil},
		{"blank names", rootPEM, []string{" "}},
		{"wildcard names", rootPEM, []string{"*.example.test"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ClientTLSConfig(tc.roots, tc.names); err == nil {
				t.Fatal("invalid client authentication config accepted")
			}
		})
	}
	cfg, err := ClientTLSConfig(rootPEM, []string{"ca.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	h := NewMutualTLS(challengeKey, DeciderFunc(func(string) bool { return true }))
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = cfg
	srv.StartTLS()
	defer srv.Close()
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(srv.Certificate())
	both := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	good, _, _ := testTLSCertificate(t, "ca", []string{"ca.example.test"}, both, false, root, rootKey)
	wifi, _, _ := testTLSCertificate(t, "device", []string{"ca.example.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, false, root, rootKey)
	wrongName, _, _ := testTLSCertificate(t, "ca", []string{"other.example.test"}, both, false, root, rootKey)
	cnOnly, _, _ := testTLSCertificate(t, "ca.example.test", nil, both, false, root, rootKey)
	untrusted, _, _ := testTLSCertificate(t, "ca", []string{"ca.example.test"}, both, false, nil, nil)
	for _, tc := range []struct {
		name string
		cert *tls.Certificate
		want bool
	}{
		{"step-ca internal leaf", &good, true}, {"no client certificate", nil, false}, {"WiFi client certificate", &wifi, false}, {"wrong SAN", &wrongName, false}, {"CN fallback", &cnOnly, false}, {"untrusted certificate", &untrusted, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientCfg := &tls.Config{RootCAs: serverRoots, MinVersion: tls.VersionTLS12}
			if tc.cert != nil {
				clientCfg.Certificates = []tls.Certificate{*tc.cert}
			}
			transport := &http.Transport{TLSClientConfig: clientCfg}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: time.Second}
			body := scepBody(t, "device", issueChallenge(t, "device", time.Now()), "wifi-scep")
			resp, err := client.Post(srv.URL+"/scep-challenge", "application/json", strings.NewReader(body))
			if !tc.want {
				if err == nil {
					_ = resp.Body.Close()
					t.Fatal("unauthorized TLS client completed request")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			data, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			var result ResponseShape
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatal(err)
			}
			if !result.Allow {
				t.Fatal("verified CA client denied")
			}
		})
	}
}
