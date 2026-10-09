package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestInstalledCertificateObservationPreservesExpiryAndCAIdentity(t *testing.T) {
	now := time.Unix(1800000000, 0)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	raw := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	seen := map[string]bool{}
	result := observeCertificateFiles(now, func(path string, secret bool, limit int64) ([]byte, error) {
		if secret || limit != 1<<20 || !strings.HasPrefix(path, "/etc/cloud-8021x/") {
			t.Fatal("observation attempted private/unbounded read", path)
		}
		seen[path] = true
		return raw, nil
	})
	if len(result) != 5 || len(seen) != 5 {
		t.Fatal("fresh node omitted a server/EC/RSA certificate", result)
	}
	labels := map[string]bool{}
	for _, row := range result {
		if row.Days != -1 {
			t.Fatal("expired observation omitted or clamped", row)
		}
		labels[row.Component+":"+row.Cert+":"+row.CA] = true
	}
	if !labels["freeradius:server:ec"] || !labels["step-ca:decrypter:rsa"] || !labels["step-ca:decrypter:ec"] {
		t.Fatal("lost CA identity", labels)
	}
	missing := observeCertificateFiles(now, func(string, bool, int64) ([]byte, error) { return nil, errors.New("unavailable") })
	if len(missing) != 0 {
		t.Fatal("missing certificate invented expiry")
	}
}

func TestSeenClientIssuerMapPreservesBothAdoptedCAsWithSameSubject(t *testing.T) {
	files := map[string][]byte{}
	for i, ca := range []string{"ec", "rsa"} {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), Subject: pkix.Name{CommonName: "Shared Wi-Fi Intermediate"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
		if err != nil {
			t.Fatal(err)
		}
		files["/etc/cloud-8021x/"+ca+"-intermediate.pem"] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	result := clientCertificateIssuerFiles(func(path string, _ bool, _ int64) ([]byte, error) { return files[path], nil })
	if len(result) != 1 || result["/CN=Shared Wi-Fi Intermediate"] != "wifi" {
		t.Fatal("duplicate public subjects lost coverage or invented specific CA", result)
	}
}
