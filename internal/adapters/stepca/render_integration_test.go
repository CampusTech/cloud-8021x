package stepca

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Development fixture export uses the product Go renderer. The actual SCEP
// harness replaces only local signer/storage/listener endpoints for isolation.
func TestExportSCEPFixtures(t *testing.T) {
	directory := os.Getenv("C8021X_SCEP_FIXTURE_OUTPUT")
	if directory == "" {
		t.Skip("SCEP runner-owned temporary directory required")
	}
	for _, mode := range []string{"legacy", "inventory"} {
		files, e := Render(RenderOptions{ECDNS: "ec.example.test", RSADNS: "rsa.example.test", ECKey: "cloudkms:projects/fixture-project/locations/global/keyRings/ca/cryptoKeys/ec/cryptoKeyVersions/1", RSAKey: "cloudkms:projects/fixture-project/locations/global/keyRings/ca/cryptoKeys/rsa/cryptoKeyVersions/1", ECDB: "postgresql://stepca:fixture@127.0.0.1/stepca?sslmode=require", RSADB: "postgresql://stepca:fixture@127.0.0.1/stepca_rsa?sslmode=require", ACME: "wifi-acme", SCEP: "wifi-scep", WebhookPort: 9444, Inventory: mode == "inventory", RSAMaterial: Material{DecrypterCert: []byte("fixture-replaced"), DecrypterKey: []byte("fixture-replaced")}})
		if e != nil {
			t.Fatal(e)
		}
		fixture := struct {
			Config    json.RawMessage   `json:"config"`
			Templates map[string]string `json:"templates"`
		}{Config: files["/etc/step-ca-rsa/config/ca.json"], Templates: map[string]string{}}
		for path, data := range files {
			if strings.Contains(path, "/templates/") {
				fixture.Templates[path] = string(data)
			}
		}
		data, e := json.Marshal(fixture)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(directory, mode+".json"), data, 0600); e != nil {
			t.Fatal(e)
		}
	}
}
