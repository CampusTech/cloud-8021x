package stepca

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSCEPReadinessRequiresLiveExactAdoptedEncryptionCertificate(t *testing.T) {
	now := time.Now()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"scep.fixture"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	expected := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	tlsCert, err := tls.X509KeyPair(expected, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	if err != nil {
		t.Fatal(err)
	}
	status := http.StatusOK
	response := der
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/scep/wifi-scep" || r.URL.Query().Get("operation") != "GetCACert" {
			t.Error("probe tried an enrollment operation", r.Method, r.URL)
		}
		w.WriteHeader(status)
		_, _ = w.Write(response)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	address := strings.TrimPrefix(server.URL, "https://")
	if err = ProbeSCEPDecrypter(context.Background(), address, "scep.fixture", "wifi-scep", expected, expected); err != nil {
		t.Fatal(err)
	}
	// Actual GetCACert's degenerate CMS envelope must also advertise this cert.
	signed, _ := asn1.Marshal(struct {
		Version int
		Digest  asn1.RawValue
		Content struct{ Type asn1.ObjectIdentifier }
		Certs   asn1.RawValue
		Signers asn1.RawValue
	}{1, asn1.RawValue{Tag: asn1.TagSet, IsCompound: true}, struct{ Type asn1.ObjectIdentifier }{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}}, asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: der}, asn1.RawValue{Tag: asn1.TagSet, IsCompound: true}})
	cms, _ := asn1.Marshal(struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue
	}{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}, asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: signed}})
	response = cms
	if err = ProbeSCEPDecrypter(context.Background(), address, "scep.fixture", "wifi-scep", expected, expected); err != nil {
		t.Fatal("CMS decrypter unavailable", err)
	}
	for name, run := range map[string]func() error{
		"expired": func() error { return verifySCEPDecrypter(cms, expected, now.Add(2*time.Hour)) },
		"wrong identity": func() error {
			return ProbeSCEPDecrypter(context.Background(), address, "foreign.fixture", "wifi-scep", expected, expected)
		},
		"missing advertised cert": func() error { return verifySCEPDecrypter([]byte("not a certificate"), expected, now) },
	} {
		t.Run(name, func(t *testing.T) {
			if run() == nil {
				t.Fatal("degraded SCEP reported ready")
			}
		})
	}
	status = http.StatusServiceUnavailable
	if err = ProbeSCEPDecrypter(context.Background(), address, "scep.fixture", "wifi-scep", expected, expected); err == nil {
		t.Fatal("unavailable handler reported ready")
	}
}
