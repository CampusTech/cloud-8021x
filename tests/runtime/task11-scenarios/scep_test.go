package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/scep"
)

// All cryptographic credentials in this file exist only inside pure tests.
// No test starts an HTTP listener, signs an installed receipt, or calls a CA.
func pureClientCredential(t *testing.T, name string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return parsed, key
}

func TestGenuineSCEPClientCSRAndRenewalWire(t *testing.T) {
	decrypter, recipientKey := pureClientCredential(t, "pure recipient")
	self, clientKey := pureClientCredential(t, "task11-scep-client")
	for _, renewal := range []bool{false, true} {
		request, err := makeSCEPRequest(clientKey, self, decrypter, "test-only-challenge", renewal)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := scep.ParsePKIMessage(request.Raw)
		if err != nil {
			t.Fatal(err)
		}
		want := scep.PKCSReq
		if renewal {
			want = scep.RenewalReq
		}
		if parsed.MessageType != want {
			t.Fatalf("wrong actual SCEP message type: %s", parsed.MessageType)
		}
		if err := parsed.DecryptPKIEnvelope(decrypter, recipientKey); err != nil {
			t.Fatal(err)
		}
		if parsed.CSR.Subject.CommonName != "task11-scep-client" || parsed.CSR.CheckSignature() != nil {
			t.Fatal("CSR identity/signature changed")
		}
		if len(parsed.CSR.DNSNames) != 0 || len(parsed.CSR.IPAddresses) != 0 || len(parsed.CSR.URIs) != 0 {
			t.Fatal("unexpected client SAN")
		}
	}
	if _, err := makeSCEPRequest(clientKey, self, decrypter, "", false); err == nil {
		t.Fatal("empty genuine broker challenge accepted")
	}
	_, wrongKey := pureClientCredential(t, "wrong key")
	if _, err := makeSCEPRequest(wrongKey, self, decrypter, "test-only-challenge", true); err == nil {
		t.Fatal("renewal mismatched signer accepted")
	}
}

func TestChallengeAndCAEndpointsAreClosed(t *testing.T) {
	good := caClientPlan{Blue: "10.203.11.31", DNS: "rsa.task11.test", Provisioner: "wifi-scep", RootSHA256: strings.Repeat("a", 64), IntermediateSHA256: strings.Repeat("b", 64), DecrypterSHA256: strings.Repeat("c", 64), BrokerCertificateSHA256: strings.Repeat("d", 64), BrokerTLSName: "localhost", BrokerTokenSHA256: strings.Repeat("e", 64)}
	if err := validateCAClientPlan(good); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*caClientPlan){func(p *caClientPlan) { p.Blue = "10.203.11.21" }, func(p *caClientPlan) { p.DNS = "real-production.example" }, func(p *caClientPlan) { p.Provisioner = "../bypass" }, func(p *caClientPlan) { p.BrokerTLSName = "arbitrary" }, func(p *caClientPlan) { p.BrokerCertificateSHA256 = "" }} {
		bad := good
		mutate(&bad)
		if validateCAClientPlan(bad) == nil {
			t.Fatalf("foreign CA client plan accepted: %+v", bad)
		}
	}
}
