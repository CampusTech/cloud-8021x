package host

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"
)

func TestFreshCollectorInstallsNativeMonitoring(t *testing.T) {
	c := config.Defaults()
	c.Hostname = "green-primary"
	c.Bootstrap.ECDNS = "ca.example.test"
	c.Bootstrap.RSADNS = "scep.example.test"
	c.Bootstrap.DatadogSite = "us5.datadoghq.com"
	files, err := collectorFiles(c, []byte(strings.Repeat("a", 32)), Accounts{}, func(f File) (SavedFile, error) { return SavedFile{File: f}, nil })
	if err != nil {
		t.Fatal(err)
	}
	found := map[string][]byte{}
	for _, f := range files {
		found[f.Path] = f.Data
	}
	for _, path := range []string{"/etc/datadog-agent/conf.d/openmetrics.d/stepca.yaml", "/etc/datadog-agent/conf.d/openmetrics.d/stepca-rsa.yaml", "/etc/datadog-agent/conf.d/http_check.d/cloud-8021x.yaml", "/etc/datadog-agent/conf.d/process.d/cloud-8021x.yaml"} {
		if len(found[path]) == 0 {
			t.Errorf("fresh node lacks native monitor producer %s", path)
		}
	}
}

func TestExportFreshMonitoringContract(t *testing.T) {
	dir := os.Getenv("C8021X_MONITORING_FIXTURE_OUTPUT")
	if dir == "" {
		t.Skip("explicit local fixture output required")
	}
	c := config.Defaults()
	c.Hostname = "green-fixture-primary"
	c.Bootstrap.ECDNS = "ec.fixture.test"
	c.Bootstrap.RSADNS = "rsa.fixture.test"
	files, err := NativeCollectorFiles(c, Accounts{})
	if err != nil {
		t.Fatal(err)
	}
	contract := map[string]string{}
	for _, f := range files {
		contract[f.Path] = string(f.Data)
	}
	raw, err := json.MarshalIndent(contract, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "native-monitoring.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	filesToWrite := map[string][]byte{"tls-ca.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})}
	for i, name := range []string{"tls", "rsa-tls", "wrong-ca"} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		privateDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		var signer any = key
		var public any = &key.PublicKey
		keyType := "EC PRIVATE KEY"
		dns := c.Bootstrap.ECDNS
		if name == "rsa-tls" {
			rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			signer, public = rsaKey, &rsaKey.PublicKey
			privateDER, keyType = x509.MarshalPKCS1PrivateKey(rsaKey), "RSA PRIVATE KEY"
			dns = c.Bootstrap.RSADNS
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: name}, NotBefore: root.NotBefore, NotAfter: root.NotAfter, DNSNames: []string{dns}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		parent, signingKey := root, any(rootKey)
		if name == "wrong-ca" {
			leaf.IsCA = true
			leaf.BasicConstraintsValid = true
			leaf.KeyUsage = x509.KeyUsageCertSign
			parent, signingKey = leaf, signer
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, parent, public, signingKey)
		if err != nil {
			t.Fatal(err)
		}
		filesToWrite[name+".crt"] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		filesToWrite[name+".key"] = pem.EncodeToMemory(&pem.Block{Type: keyType, Bytes: privateDER})
	}
	for name, data := range filesToWrite {
		if err = os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
