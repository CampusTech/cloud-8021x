package stepca

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRenderPreservesIndependentCADBsAndProvisioners(t *testing.T) {
	o := RenderOptions{ECDNS: "ec.example.test", RSADNS: "rsa.example.test", ECKey: "cloudkms:projects/fixture-project/locations/global/keyRings/ca/cryptoKeys/ec/cryptoKeyVersions/1", RSAKey: "cloudkms:projects/fixture-project/locations/global/keyRings/ca/cryptoKeys/rsa/cryptoKeyVersions/1", ECDB: "postgresql://stepca:secret@10.0.0.3/stepca?sslmode=require", RSADB: "postgresql://stepca:secret@10.0.0.3/stepca_rsa?sslmode=require", ACME: "wifi-acme", SCEP: "wifi-scep", WebhookPort: 8445, Inventory: true, RSAMaterial: Material{DecrypterCert: []byte("cert"), DecrypterKey: []byte("key")}}
	files, e := Render(o)
	if e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"/etc/step-ca/config/ca.json", "/etc/step-ca-rsa/config/ca.json"} {
		if !json.Valid(files[path]) {
			t.Fatal(path)
		}
	}
	ec, rsa := string(files["/etc/step-ca/config/ca.json"]), string(files["/etc/step-ca-rsa/config/ca.json"])
	for _, s := range []string{"device-attest-01", "AUTHORIZING", "2160h", "postgresql://stepca:secret@10.0.0.3/stepca?sslmode=require"} {
		if !strings.Contains(ec, s) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"SCEPCHALLENGE", "decrypterKeyPEM", "stepca_rsa", "2160h"} {
		if !strings.Contains(rsa, s) {
			t.Fatal(s)
		}
	}
	if strings.Contains(ec, "SCEP") || strings.Contains(rsa, "ACME") {
		t.Fatal("provisioners mixed")
	}
	if !strings.Contains(string(files["/etc/step-ca-rsa/templates/x509/wifi-scep.tpl"]), "cloud-8021x-inventory") {
		t.Fatal("inventory CN lost")
	}
}
