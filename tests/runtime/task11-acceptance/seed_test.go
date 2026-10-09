package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/stepca"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/migration"
)

func TestSeedIsGenuineOriginalStateWithoutAccountingOrReceiptKeys(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	files, err := generateSeed(seedSpec{Project: "task11-acceptance", ECDNS: "ec.task11.test", RSADNS: "rsa.task11.test", ServerDNS: "radius.task11.test", ECDB: "postgresql://stepca:synthetic@10.203.11.11/stepca?sslmode=verify-full", RSADB: "postgresql://stepca:synthetic@10.203.11.11/stepca_rsa?sslmode=verify-full", ObservedAt: now, Remote: &remoteSeedSpec{ApplicationSHA256: strings.Repeat("a", 64), FleetAuthorization: "Bearer synthetic-private-test-token", IntakeHost: "otlp.us5.datadoghq.com", IntakeAPIKey: "synthetic-private-test-key"}})
	if err != nil {
		t.Fatal(err)
	}
	for name := range files {
		if strings.Contains(name, "parallel-source.key") || strings.Contains(name, "rollback-") || strings.Contains(name, "activation") || strings.Contains(name, "radacct") || strings.Contains(name, "checkpoint") {
			t.Fatalf("forbidden fabricated product state: %s", name)
		}
	}
	for _, base := range []string{"/etc/step-ca", "/etc/step-ca-rsa"} {
		rootBlock, _ := pem.Decode(files["source"+base+"/certs/root_ca.crt"])
		interBlock, _ := pem.Decode(files["source"+base+"/certs/intermediate_ca.crt"])
		if rootBlock == nil || interBlock == nil {
			t.Fatal("missing real certificates")
		}
		root, err := x509.ParseCertificate(rootBlock.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		inter, err := x509.ParseCertificate(interBlock.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if inter.CheckSignatureFrom(root) != nil || !root.IsCA || !inter.IsCA {
			t.Fatal("synthetic CA chain invalid")
		}
	}
	if err = stepca.ValidateAdoptedLoopback(files["source/etc/acme-authz-webhook/server.crt"], files["source/etc/acme-authz-webhook/server.key"], now); err != nil {
		t.Fatal(err)
	}
	snapshot, err := domain.DecodeSnapshot(bytes.NewReader(files["source/etc/freeradius/3.0/device-policy-cache.json"]))
	if err != nil {
		t.Fatal(err)
	}
	state, err := migration.DecodeCertificates(files["source/var/lib/cloud-8021x/certificate-state.json"])
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Certificates) != 1 || len(state.Commands) != 1 || len(state.Hosts) != 1 {
		t.Fatal("no real fingerprint and pending guard seeded")
	}
	for fp, rec := range snapshot.Certificates {
		h := state.Hosts[syntheticDevice]
		if h.Observation == nil || h.Observation.Fingerprints[0] != fp || rec.ObservedAt == nil || *rec.ObservedAt != domain.Unix(now) {
			t.Fatal("observation/policy identity or original timestamp differs")
		}
	}
	if _, err = approvedGreenHosts(files["api/seed.json"], strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	var cloud map[string]json.RawMessage
	if json.Unmarshal(files["api/seed.json"], &cloud) != nil || len(cloud["keys"]) == 0 || len(cloud["secrets"]) == 0 {
		t.Fatal("missing real cloud import material")
	}
}
