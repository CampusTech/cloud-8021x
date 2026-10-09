package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/templates/systemd"
	seed "github.com/CampusTech/cloud-8021x/tests/runtime/task11-assembly-seed/contract"
)

func nativeInputs(t *testing.T) (seed.Input, map[string][]byte) {
	t.Helper()
	s := configInput()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic PostgreSQL"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	raw, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
	s.PostgresCA.SHA256 = digest(ca)
	files := map[string][]byte{s.PostgresCA.Path: ca}
	for _, n := range originalNames {
		files[n] = []byte("unchanged original fixture bytes " + n)
	}
	secrets := map[string]map[string]string{}
	for _, ref := range append(seed.Credentials(s.Project), seed.SourceCredentials(s.Project)...) {
		value := strings.Repeat("a", 48)
		if strings.Contains(ref.ID, "postgres-") {
			db := seed.Database
			if strings.Contains(ref.ID, "-blue-") {
				db = "cloud8021x_task11_blue"
			}
			role := "runtime"
			if strings.Contains(ref.ID, "migration") {
				role = "migrate"
			}
			if strings.Contains(ref.ID, "native") {
				role = "native"
			}
			value = "postgresql://" + db + "_" + role + ":synthetic-password@10.203.11.11:5432/" + db + "?sslmode=require"
		}
		resource := strings.Replace(ref.Resource, s.Project, s.ProjectNumber, 1)
		secrets[resource] = map[string]string{"1": base64.StdEncoding.EncodeToString([]byte(value))}
	}
	files["api/seed.json"], err = json.Marshal(map[string]any{"secrets": secrets})
	if err != nil {
		t.Fatal(err)
	}
	return s, files
}
func TestSourceNativeUsesShippingRendererWithIndependentBlueTLSLedger(t *testing.T) {
	s, files := nativeInputs(t)
	out, err := sourceCandidates(s, files, "primary", strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	sql := string(out["/etc/freeradius/3.0/mods-enabled/sql"].Data)
	if !strings.Contains(sql, "cloud8021x_task11_blue") || strings.Contains(sql, "cloud8021x_task11_green") || !strings.Contains(sql, "/etc/cloud-8021x/postgres-ca.pem") {
		t.Fatal("rendered native SQL lost isolated authenticated DB")
	}
	rest := string(out["/etc/freeradius/3.0/mods-enabled/rest"].Data)
	if !strings.Contains(rest, "127.0.0.1:9082") {
		t.Fatal("native original policy endpoint changed")
	}
	for _, name := range originalNames {
		if strings.HasPrefix(name, "source/") {
			c := out[strings.TrimPrefix(name, "source")]
			if !bytes.Equal(c.Data, files[name]) {
				t.Fatalf("original bytes changed: %s", name)
			}
		}
	}
	if out["/etc/cloud8021x-task11-source-provenance.json"].Mode != 0444 || out["/run/radius-accounting-key"].Owner != "cloud8021x" {
		t.Fatal("protected source projection or unprivileged Class access differs")
	}
	if out["/etc/cloud8021x-task11-webhook.env"].Mode != 0600 {
		t.Fatal("private compatibility credentials exposed")
	}
	s.PostgresCA.SHA256 = strings.Repeat("a", 64)
	if _, err = sourceCandidates(s, files, "primary", strings.Repeat("b", 64)); err == nil {
		t.Fatal("wrong TLS CA pin accepted")
	}
}
func TestRebootLeafDirectoryMatchesActualNativeWriterAndRootVerifier(t *testing.T) {
	s, files := nativeInputs(t)
	out, err := sourceCandidates(s, files, "primary", strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	shipping, err := systemd.Render()
	if err != nil {
		t.Fatal(err)
	}
	rule := "d /run/radius-verified-leaves 0700 freerad freerad -"
	if !strings.Contains(string(shipping["/etc/tmpfiles.d/cloud-8021x.conf"]), rule) {
		t.Fatal("shipping ownership contract changed")
	}
	if !strings.Contains(string(out["/etc/tmpfiles.d/task11-source.conf"].Data), rule) {
		t.Fatal("source reboot denies actual native leaf writer")
	}
	radius := string(out["/etc/freeradius/3.0/radiusd.conf"].Data)
	eap := string(out["/etc/freeradius/3.0/mods-enabled/eap"].Data)
	if !strings.Contains(radius, "user = freerad") || !strings.Contains(eap, "/run/radius-verified-leaves") {
		t.Fatal("test does not cover actual rendered native leaf writer")
	}
	if !bytes.Equal(out["/etc/sudoers.d/cloud-8021x"].Data, shipping["/etc/sudoers.d/cloud-8021x"]) {
		t.Fatal("constrained root verifier changed")
	}
}
