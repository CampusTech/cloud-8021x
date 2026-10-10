package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
	"github.com/CampusTech/cloud-8021x/internal/domain"
)

func TestSeenCertificateObservationRequiresVerifiedIdentityAndNativeFields(t *testing.T) {
	now := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	key := []byte(strings.Repeat("k", 32))
	for _, id := range []string{"fleet:owned-acme", "byod:opaque-uuid", "fleet:windows-uuid"} {
		t.Run(id, func(t *testing.T) {
			token, err := binding.Issue(key, binding.Attribution{DeviceID: domain.DeviceID(id), Fingerprint: strings.Repeat("a", 64)}, "office", "aa:bb:cc:dd:ee:ff", now)
			if err != nil {
				t.Fatal(err)
			}
			enrich := WithCertificateExpiry(InventoryEnricher(key, nil, time.Hour), map[string]string{"/CN=Wi-Fi EC": "ec", "/CN=Wi-Fi RSA": "rsa"})
			for _, scenario := range []string{"valid", "other-issuer", "wrong-class", "wrong-station", "multiple", "malformed", "missing", "rejected", "expired-utc-century", "generalized", "shared-dn"} {
				t.Run(scenario, func(t *testing.T) {
					r := Record{Values: map[string][]string{"Class": {token}, "C8021X-Station": {"aa:bb:cc:dd:ee:ff"}, "C8021X-Station-Count": {"1"}, "C8021X-Cert-Expiration": {"261010000000Z"}, "C8021X-Cert-Issuer": {"/CN=Wi-Fi EC"}}}
					e := Event{Event: "Access-Accept", Location: "office", Received: now}
					ca := "ec"
					if id != "fleet:owned-acme" {
						r.Values["C8021X-Cert-Issuer"] = []string{"/CN=Wi-Fi RSA"}
						ca = "rsa"
					}
					observer := enrich
					switch scenario {
					case "shared-dn":
						r.Values["C8021X-Cert-Issuer"] = []string{"/CN=Shared Wi-Fi"}
						ca = "wifi"
						observer = WithCertificateExpiry(InventoryEnricher(key, nil, time.Hour), map[string]string{"/CN=Shared Wi-Fi": "wifi"})
					case "other-issuer":
						r.Values["C8021X-Cert-Issuer"] = []string{"/CN=Other CA"}
					case "wrong-class":
						r.Values["Class"] = []string{"forged"}
					case "wrong-station":
						r.Values["C8021X-Station"] = []string{"11:22:33:44:55:66"}
					case "multiple":
						r.Values["C8021X-Cert-Expiration"] = []string{"261010000000Z", "261011000000Z"}
					case "malformed":
						r.Values["C8021X-Cert-Expiration"] = []string{"261399000000Z"}
					case "missing":
						delete(r.Values, "C8021X-Cert-Issuer")
					case "generalized":
						r.Values["C8021X-Cert-Expiration"] = []string{"20261010000000Z"}
					case "expired-utc-century":
						r.Values["C8021X-Cert-Expiration"] = []string{"510101000000Z"}
					case "rejected":
						e.Event = "Access-Reject"
					}
					observer(&e, r)
					raw, _ := json.Marshal(e)
					var payload map[string]json.RawMessage
					_ = json.Unmarshal(raw, &payload)
					observed := len(payload["certificate_observation"]) > 0
					if observed != (scenario == "valid" || scenario == "other-issuer" || scenario == "generalized" || scenario == "shared-dn") {
						t.Fatalf("non-authorizing observation presence=%v scenario=%s", observed, scenario)
					}
					if e.Event != map[bool]string{true: "Access-Reject", false: "Access-Accept"}[scenario == "rejected"] {
						t.Fatal("observation changed auth outcome")
					}
					if scenario == "valid" || scenario == "generalized" || scenario == "shared-dn" {
						var ob struct {
							Expires int64  `json:"expires_at"`
							CA      string `json:"ca_instance"`
						}
						_ = json.Unmarshal(payload["certificate_observation"], &ob)
						if ob.Expires != now.Add(24*time.Hour).Unix() || ob.CA != ca {
							t.Fatal(string(payload["certificate_observation"]))
						}
					}
					if strings.Contains(string(raw), "Wi-Fi") || strings.Contains(string(raw), "Other CA") {
						t.Fatal("raw issuer leaked")
					}
				})
			}
		})
	}
}

func TestNativeIssuerClassificationUsesExactAdoptedPublicSubject(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, cn := range []string{"Wi-Fi Intermediate CA", "Wi-Fi RSA Intermediate CA", "ambiguous/name"} {
		cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		name, err := NativeIssuerName(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		if cn == "ambiguous/name" {
			if err == nil {
				t.Fatal("guessed unsupported escaped issuer")
			}
			continue
		}
		if err != nil || name != "/CN="+cn {
			t.Fatal(name, err)
		}
	}
}
