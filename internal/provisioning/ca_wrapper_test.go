package provisioning

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/adapters/stepca"
)

// The original CA JSON is read from the byte-preserved startup fixture, never
// synthesized from the new renderer. Terraform uses only mocked providers.
func TestTerraformCAWrappersAdoptOriginalECAndRSA(t *testing.T) {
	if os.Getenv("C8021X_TERRAFORM_FIXTURE") != "1" {
		t.Skip("explicit offline Terraform fixture required")
	}
	cmd := exec.Command("terraform", "-chdir=../../terraform/private-green", "test", "-json", "-verbose")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("mock Terraform failed: %v\n%s", err, out)
	}
	dsns := map[string]string{}
	for _, line := range bytes.Split(out, []byte("\n")) {
		var event struct {
			Run  string `json:"@testrun"`
			Plan struct {
				Changes []struct {
					Address string `json:"address"`
					Change  struct {
						After struct {
							Secret string `json:"secret_data"`
						} `json:"after"`
					} `json:"change"`
				} `json:"resource_changes"`
			} `json:"test_plan"`
		}
		if json.Unmarshal(line, &event) != nil || event.Run != "private_owners_and_preserved_ca_password" {
			continue
		}
		for _, change := range event.Plan.Changes {
			for _, db := range []string{"stepca", "stepca_rsa"} {
				if change.Address == `google_secret_manager_secret_version.ca_dsn["`+db+`"]` {
					dsns[db] = change.Change.After.Secret
				}
			}
		}
	}
	source, err := os.ReadFile("../../tests/legacy/scripts/startup.sh")
	if err != nil {
		t.Fatal(err)
	}
	o := stepca.RenderOptions{ECDNS: "ec.example.test", RSADNS: "rsa.example.test", ECKey: "cloudkms:projects/fixture-project/locations/global/keyRings/ca/cryptoKeys/ec/cryptoKeyVersions/1", RSAKey: "cloudkms:projects/fixture-project/locations/global/keyRings/ca/cryptoKeys/rsa/cryptoKeyVersions/1", ECDB: dsns["stepca"], RSADB: dsns["stepca_rsa"], ACME: "wifi-acme", SCEP: "wifi-scep", WebhookPort: 9444, RSAMaterial: stepca.Material{DecrypterCert: []byte("synthetic-cert"), DecrypterKey: []byte("synthetic-key")}}
	replacer := strings.NewReplacer(
		"$STEPPATH", "/etc/step-ca", "${smallstep_signing_key_uri}", o.ECKey, "${smallstep_rsa_signing_key_uri}", o.RSAKey,
		"${smallstep_ca_dns_name}", o.ECDNS, "${smallstep_ca_rsa_dns_name}", o.RSADNS,
		"${smallstep_db_user}", "stepca", "$${SMALLSTEP_DB_PASSWORD}", "OriginalCAPassword0123456789", "${smallstep_db_host}", "10.0.2.2", "${smallstep_db_name}", "stepca",
		"${smallstep_acme_name}", o.ACME, "${smallstep_scep_rsa_name}", o.SCEP, "${acme_webhook_url}", "https://127.0.0.1:9444/authorize", "${webhook_port}", "9444",
		"$${RSA_SCEP_DECRYPTER_CERT_B64}", base64.StdEncoding.EncodeToString(o.RSAMaterial.DecrypterCert), "$${RSA_SCEP_DECRYPTER_KEY_B64}", base64.StdEncoding.EncodeToString(o.RSAMaterial.DecrypterKey))
	for i, db := range []string{"stepca", "stepca_rsa"} {
		t.Run(db, func(t *testing.T) {
			delimiter := []string{"CAJSON", "CARSAJSON"}[i]
			parts := strings.SplitN(string(source), "<<"+delimiter+"\n", 2)
			if len(parts) != 2 {
				t.Fatal("legacy JSON missing")
			}
			original := strings.SplitN(parts[1], "\n"+delimiter, 2)[0]
			original = regexp.MustCompile(`(?m)^%\{ (?:if acme_webhook_url != "" ~|endif ~)\}\n`).ReplaceAllString(original, "")
			raw := []byte(replacer.Replace(original))
			var expected map[string]any
			if err := json.Unmarshal(raw, &expected); err != nil {
				t.Fatal(err)
			}
			if dsns[db] == "" {
				t.Fatal("planned DSN missing")
			}
			expected["db"].(map[string]any)["dataSource"] = dsns[db]
			comparison, err := json.Marshal(expected)
			if err != nil {
				t.Fatal(err)
			}
			if err := stepca.ValidateAdoptedConfig(raw, comparison); err != nil {
				t.Fatalf("generated wrapper cannot adopt original %s JSON: %v", db, err)
			}
			rendered, err := stepca.Render(o)
			if err != nil {
				t.Fatal(err)
			}
			path := []string{"/etc/step-ca/config/ca.json", "/etc/step-ca-rsa/config/ca.json"}[i]
			if err := stepca.ValidateAdoptedConfig(raw, rendered[path]); err != nil {
				t.Fatalf("actual Go renderer cannot adopt original JSON: %v", err)
			}
		})
	}
}
