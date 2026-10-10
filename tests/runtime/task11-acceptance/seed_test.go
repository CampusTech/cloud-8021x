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
	// The initial original CA configs must already target the independently fixed
	// source compatibility and adopted green webhook listener (9444). Adoption
	// preserves these bytes; it must never repair a pinned original callback.
	for _, ca := range []struct{ name, path, endpoint, kind string }{
		{"ec", "source/etc/step-ca/config/ca.json", "/authorize", "AUTHORIZING"},
		{"rsa", "source/etc/step-ca-rsa/config/ca.json", "/scep-challenge", "SCEPCHALLENGE"},
	} {
		t.Run(ca.name+"-webhook-callback", func(t *testing.T) {
			var rendered struct {
				Authority struct {
					Provisioners []struct {
						Options struct {
							Webhooks []struct {
								URL  string `json:"url"`
								Kind string `json:"kind"`
							} `json:"webhooks"`
						} `json:"options"`
					} `json:"provisioners"`
				} `json:"authority"`
			}
			if err := json.Unmarshal(files[ca.path], &rendered); err != nil {
				t.Fatal(err)
			}
			if len(rendered.Authority.Provisioners) != 1 || len(rendered.Authority.Provisioners[0].Options.Webhooks) != 1 {
				t.Fatal("actual generated CA callback missing or ambiguous")
			}
			callback := rendered.Authority.Provisioners[0].Options.Webhooks[0]
			if callback.URL != "https://127.0.0.1:9444"+ca.endpoint || callback.Kind != ca.kind {
				t.Fatalf("original %s callback differs from fixed source/green listener: %s (%s)", ca.name, callback.URL, callback.Kind)
			}
		})
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
	assertUnenrolledSeedClient(t, files, snapshot, state, now)
	var cloud map[string]json.RawMessage
	if json.Unmarshal(files["api/seed.json"], &cloud) != nil || len(cloud["keys"]) == 0 || len(cloud["secrets"]) == 0 {
		t.Fatal("missing real cloud import material")
	}
}
