package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	audit "github.com/CampusTech/cloud-8021x/tests/runtime/task11-passive-audit/contract"
)

func TestPassiveManifestDerivesActualAdoptedTransforms(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	spec := seedSpec{Project: "task11-acceptance", ECDNS: "ec.task11.test", RSADNS: "rsa.task11.test", ServerDNS: "radius.task11.test", ECDB: "postgresql://stepca:synthetic@10.203.11.11/stepca?sslmode=verify-full", RSADB: "postgresql://stepca:synthetic@10.203.11.11/stepca_rsa?sslmode=verify-full", ObservedAt: now}
	files, err := generateSeed(spec)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Bootstrap.ECDNS = spec.ECDNS
	cfg.Bootstrap.RSADNS = spec.RSADNS
	cfg.Bootstrap.ServerDNS = spec.ServerDNS
	cfg.Bootstrap.ECKMS = "cloudkms:projects/task11-acceptance/locations/us-central1/keyRings/task11/cryptoKeys/ec/cryptoKeyVersions/1"
	cfg.Bootstrap.RSAKMS = strings.Replace(cfg.Bootstrap.ECKMS, "/ec/", "/rsa/", 1)
	cfg.Bootstrap.ACMEProvisioner = "wifi-acme"
	cfg.Bootstrap.SCEPProvisioner = "wifi-scep"
	cfg.Inventory.Fleet.ManagedCertificates = true
	cfg.Listeners.Webhook.Address = "127.0.0.1:9444"
	a := adoption.Authorization{Policy: files["source/etc/freeradius/3.0/device-policy-cache.json"], Certificates: files["source/var/lib/cloud-8021x/certificate-state.json"], ClassSHA256: adoption.Digest(files["source/run/radius-accounting-key"]), Native: &adoption.NativeIdentity{WebhookCertificate: files["source/etc/acme-authz-webhook/server.crt"], WebhookKey: files["source/etc/acme-authz-webhook/server.key"], ECConfig: files["source/etc/step-ca/config/ca.json"], RSAConfig: files["source/etc/step-ca-rsa/config/ca.json"], ECTemplate: files["source/etc/step-ca/templates/x509/wifi-acme.tpl"], RSATemplate: files["source/etc/step-ca-rsa/templates/x509/wifi-scep.tpl"]}}
	trust := bytes.Join([][]byte{files["source/etc/step-ca/certs/intermediate_ca.crt"], files["source/etc/step-ca/certs/root_ca.crt"], files["source/etc/step-ca-rsa/certs/intermediate_ca.crt"], files["source/etc/step-ca-rsa/certs/root_ca.crt"]}, nil)
	a.TrustSHA256 = adoption.Digest(trust)
	pin := strings.Repeat("a", 64)
	originalManifest, err := originalManifestBytes(files)
	if err != nil {
		t.Fatal(err)
	}
	originalPin := adoption.Digest(originalManifest)
	m, err := derivePassiveManifest(cfg, a, files, originalPin, pin, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Slots) != len(audit.Slots) || m.Slots["client-trust"] != adoption.Digest(trust) || m.Slots["client-trust"] == adoption.Digest(files["source/etc/freeradius/3.0/certs/ca.pem"]) {
		t.Fatal("installed trust copied raw source roots instead of actual adoption")
	}
	var api struct {
		Secrets map[string]map[string]string `json:"secrets"`
	}
	if json.Unmarshal(files["api/seed.json"], &api) != nil {
		t.Fatal("seed")
	}
	leaf, _ := base64.StdEncoding.DecodeString(api.Secrets["projects/111222333444/secrets/radius-smallstep-server-cert"]["1"])
	chain := append(leaf, files["source/etc/step-ca/certs/intermediate_ca.crt"]...)
	if m.Slots["native-server"] != adoption.Digest(chain) || m.Slots["server-cache"] != m.Slots["native-server"] || m.Slots["inventory"] != adoption.Digest(a.Policy) {
		t.Fatal("production adopted output differs")
	}
	mismatched := cfg
	mismatched.Listeners.Webhook.Address = "127.0.0.1:9080"
	if _, err = derivePassiveManifest(mismatched, a, files, originalPin, pin, now); err == nil {
		t.Fatal("mismatched configured webhook callback accepted")
	}
	preserved, err := originalManifestBytes(files)
	if err != nil || adoption.Digest(preserved) != originalPin {
		t.Fatal("mismatched callback altered immutable original bundle", err)
	}
	a.Native.WebhookKey = []byte("replacement")
	if _, err = derivePassiveManifest(cfg, a, files, originalPin, pin, now); err == nil {
		t.Fatal("changed inherited identity accepted")
	}
}
func TestDeactivatedInventoryAllowsOnlyApprovedRemoteIdentityAndPreservedLeafAuthority(t *testing.T) {
	at := domain.Timestamp(1800000000)
	fp := strings.Repeat("a", 64)
	original := domain.Snapshot{Version: 2, UpdatedAt: at, Identities: map[string]*domain.DeviceRecord{syntheticDevice: {DeviceID: "fleet:1", Groups: []domain.GroupID{"fleet:1"}, Enrolled: true, ObservedAt: &at}}, Certificates: map[string]*domain.DeviceRecord{fp: {DeviceID: "fleet:1", Groups: []domain.GroupID{"fleet:1"}, Enrolled: true, ObservedAt: &at}}, HardwareSerials: map[string]*domain.DeviceRecord{}}
	before, _ := json.Marshal(original)
	next := original.Clone()
	next.UpdatedAt++
	next.Identities[syntheticDevice].ObservedAt = nil
	next.Identities[syntheticWindows] = &domain.DeviceRecord{DeviceID: "fleet:2", Groups: []domain.GroupID{"fleet:1"}, Enrolled: true}
	next.Devices = map[domain.DeviceID]*domain.DeviceMetadata{"fleet:1": {}, "fleet:2": {}}
	contract, _ := makeRemoteContract(remoteSeedSpec{ApplicationSHA256: fp, FleetAuthorization: "Bearer synthetic-private-token", IntakeHost: "otlp.us5.datadoghq.com", IntakeAPIKey: "synthetic-private-key"}, time.Unix(1800000000, 0))
	seed, _ := json.Marshal(map[string]any{"contract": contract})
	raw, _ := json.Marshal(next)
	if hash, err := deactivatedInventory(config.Defaults(), before, raw, seed); err != nil || hash != adoption.Digest(raw) {
		t.Fatal("approved real publication rejected", err)
	}
	missingWindows := next.Clone()
	delete(missingWindows.Identities, syntheticWindows)
	missing, err := json.Marshal(missingWindows)
	if err != nil {
		t.Fatal(err)
	}
	for name, publication := range map[string][]byte{"missing-windows": missing, "unchanged-original": before} {
		t.Run(name, func(t *testing.T) {
			if _, err := deactivatedInventory(config.Defaults(), before, publication, seed); err == nil {
				t.Fatal("incomplete two-host publication accepted")
			}
		})
	}
	for _, change := range []func(*domain.Snapshot){func(v *domain.Snapshot) { v.Certificates[fp].ObservedAt = nil }, func(v *domain.Snapshot) { v.Certificates[strings.Repeat("b", 64)] = v.Identities[syntheticWindows] }, func(v *domain.Snapshot) { v.Identities[syntheticWindows].Groups = []domain.GroupID{"fleet:99"} }, func(v *domain.Snapshot) { v.Identities["unknown"] = v.Identities[syntheticDevice] }} {
		bad := next.Clone()
		change(&bad)
		wire, _ := json.Marshal(bad)
		if _, err := deactivatedInventory(config.Defaults(), before, wire, seed); err == nil {
			t.Fatal("new or changed authority accepted")
		}
	}
}

func TestDeactivatedInventoryRejectsRemoteEnrollmentContradiction(t *testing.T) {
	at := domain.Timestamp(1800000000)
	rec := &domain.DeviceRecord{DeviceID: "fleet:1", Groups: []domain.GroupID{"fleet:1"}, Enrolled: true, ObservedAt: &at}
	original := domain.Snapshot{Version: 2, UpdatedAt: at, Identities: map[string]*domain.DeviceRecord{syntheticDevice: rec}, Certificates: map[string]*domain.DeviceRecord{strings.Repeat("a", 64): rec}, HardwareSerials: map[string]*domain.DeviceRecord{}}
	before, _ := json.Marshal(original)
	next := original.Clone()
	next.Identities[syntheticWindows] = &domain.DeviceRecord{DeviceID: "fleet:2", Groups: []domain.GroupID{"fleet:1"}, Enrolled: true}
	raw, _ := json.Marshal(next)
	remote, _ := makeRemoteContract(remoteSeedSpec{ApplicationSHA256: strings.Repeat("a", 64), FleetAuthorization: "Bearer synthetic-private-token", IntakeHost: "otlp.us5.datadoghq.com", IntakeAPIKey: "synthetic-private-key"}, time.Unix(int64(at), 0))
	remote.Fleet.Hosts[1].MDM = json.RawMessage(`{"enrollment_status":"Off","profiles":[]}`)
	seed, _ := json.Marshal(map[string]any{"contract": remote})
	if _, err := deactivatedInventory(config.Defaults(), before, raw, seed); err == nil {
		t.Fatal("published enrolled identity contradicted approved remote enrollment")
	}
}
