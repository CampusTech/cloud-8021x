package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"slices"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/migration"
)

func assertUnenrolledSeedClient(t *testing.T, files map[string][]byte, policy domain.Snapshot, state migration.LegacyCertificateState, now time.Time) {
	t.Helper()
	pair, e := tls.X509KeyPair(files["nas/reject-client.pem"], files["nas/reject-client.key"])
	if e != nil || len(pair.Certificate) != 2 {
		t.Fatal("new seed lacks genuine independent trusted rejection client", e)
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	rootBlock, _ := pem.Decode(files["source/etc/step-ca/certs/root_ca.crt"])
	root, e := x509.ParseCertificate(rootBlock.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	inter, e := x509.ParseCertificate(pair.Certificate[1])
	if e != nil {
		t.Fatal(e)
	}
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	inters.AddCert(inter)
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
		t.Fatal(e)
	}
	if leaf.Subject.CommonName != "22222222-3333-4444-8555-666666666666" || leaf.IsCA || leaf.KeyUsage != x509.KeyUsageDigitalSignature || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(leaf.UnknownExtKeyUsage)+len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses)+len(leaf.URIs) != 0 {
		t.Fatal("negative client constraints differ")
	}
	fp := adoption.Digest(leaf.Raw)
	if policy.Identities[leaf.Subject.CommonName] != nil || policy.Certificates[fp] != nil {
		t.Fatal("negative client published into policy")
	}
	if _, ok := state.Hosts[leaf.Subject.CommonName]; ok {
		t.Fatal("negative client enrolled into original state")
	}
	for _, h := range state.Hosts {
		if h.Observation != nil && slices.Contains(h.Observation.Fingerprints, fp) {
			t.Fatal("negative fingerprint observed")
		}
	}
	for _, c := range state.Commands {
		if _, ok := c.Hosts[leaf.Subject.CommonName]; ok {
			t.Fatal("negative pending command fabricated")
		}
	}
	if bytes.Equal(files["nas/client.key"], files["nas/reject-client.key"]) || bytes.Equal(files["nas/client.pem"], files["nas/reject-client.pem"]) {
		t.Fatal("positive client replaced/reused")
	}
}
