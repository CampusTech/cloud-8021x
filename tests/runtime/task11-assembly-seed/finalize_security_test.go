package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-assembly-seed/contract"
)

func TestFinalizationRefusesChangedOrPreviouslyFinalizedInputs(t *testing.T) {
	for _, which := range []string{"pin", "manifest", "finalized", "CA password", "CA trust", "unexpected prior TLS"} {
		t.Run(which, func(t *testing.T) {
			p, files := syntheticOriginal(t)
			switch which {
			case "pin":
				p.SeedSHA256 = strings.Repeat("e", 64)
			case "manifest":
				files[originalNames[2]] = []byte("changed")
			case "unexpected prior TLS":
				files["api/tls.pem"] = []byte("prior protected TLS")
			case "finalized":
				files["assembly-input.json"] = []byte("already")
			case "CA password", "CA trust":
				var spec seedSpec
				_ = json.Unmarshal(files["spec.json"], &spec)
				if which == "CA password" {
					spec.RSADB = strings.Replace(spec.RSADB, "synthetic", "different", 1)
				} else {
					spec.ECDB = strings.Replace(spec.ECDB, "/etc/cloud-8021x/postgres-ca.pem", "/etc/other.pem", 1)
				}
				files["spec.json"], _ = json.Marshal(spec)
				files["original-manifest.json"], _ = originalManifest(files)
				p.ManifestSHA256 = digest(files["original-manifest.json"])
			}
			if _, err := finalize(p, files); err == nil {
				t.Fatal("changed original accepted")
			}
		})
	}
}
func TestFinalTLSRoutesAndSeparateDatabaseAuthority(t *testing.T) {
	p, files := syntheticOriginal(t)
	b, err := finalize(p, files)
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"api", "postgres"} {
		certpath, keypath, capath := "api/tls.pem", "api/tls.key", "api/ca.pem"
		names := []string{"secretmanager.googleapis.com", "cloudkms.googleapis.com", "sqladmin.googleapis.com", "fleet.task11.test", "otlp.us5.datadoghq.com", "otlp.task11.test", "unifi.task11.test"}
		if family == "postgres" {
			certpath, keypath, capath = "postgres/server.pem", "postgres/server.key", "postgres/postgres-ca.pem"
			names = []string{"10.203.11.11"}
		}
		pair, e := tls.X509KeyPair(b.Original[certpath], b.Original[keypath])
		if e != nil {
			t.Fatal(e)
		}
		leaf, e := x509.ParseCertificate(pair.Certificate[0])
		if e != nil {
			t.Fatal(e)
		}
		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM(b.Original[capath])
		for _, name := range names {
			if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name, CurrentTime: p.CollectionEpoch}); e != nil {
				t.Fatalf("SAN verification failed %s: %v", name, e)
			}
		}
		if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "production.example", CurrentTime: p.CollectionEpoch}); e == nil {
			t.Fatal("unexpected TLS identity accepted")
		}
	}
	var cloud cloudSeed
	_ = json.Unmarshal(b.Original["api/seed.json"], &cloud)
	if len(cloud.Routes) != 4 {
		t.Fatal("route scope differs")
	}
	var sql struct {
		ConnectionName string `json:"connectionName"`
		ServerCAMode   string `json:"serverCaMode"`
		ServerCACert   struct {
			Cert string `json:"cert"`
		} `json:"serverCaCert"`
	}
	_ = json.Unmarshal(cloud.Routes[0].Response, &sql)
	if sql.ConnectionName != b.Input.SQLInstance || sql.ServerCAMode != "GOOGLE_MANAGED_INTERNAL_CA" || digest([]byte(sql.ServerCACert.Cert)) != b.Input.PostgresCA.SHA256 || cloud.Routes[0].Authorization != "Bearer task11-synthetic-token-not-a-cloud-credential" {
		t.Fatal("SQLAdmin attestation differs")
	}
	for _, r := range cloud.Routes {
		if r.Method != "GET" || r.Mutation || r.Status != 200 || r.BodySHA256 != digest(nil) {
			t.Fatal("overscoped route")
		}
	}
	for _, set := range [][]contract.Credential{b.Input.Credentials, b.Input.SourceCredentials} {
		for _, ref := range set {
			encoded := cloud.Secrets[strings.Replace(ref.Resource, b.Input.Project, contract.ProjectNumber, 1)]["1"]
			raw, e := base64.StdEncoding.DecodeString(encoded)
			if e != nil || len(raw) == 0 {
				t.Fatal("referenced credential absent")
			}
			if strings.Contains(ref.ID, "blue") && (!bytes.Contains(raw, []byte("cloud8021x_task11_blue")) || bytes.Contains(raw, []byte("cloud8021x_task11_green"))) {
				t.Fatal("blue DSN points green")
			}
		}
	}
	sqlText := string(b.Original["postgres/init.sql"])
	for _, forbidden := range []string{"CREATE TABLE", "INSERT INTO", "GRANT ALL", "SUPERUSER PASSWORD"} {
		if strings.Contains(sqlText, forbidden) {
			t.Fatal("fabricated schema/authority")
		}
	}
	if !strings.Contains(sqlText, "CONNECTION LIMIT 16") || !strings.Contains(sqlText, "CONNECTION LIMIT 4") || !strings.Contains(sqlText, "CONNECTION LIMIT 2") {
		t.Fatal("aggregate role budget lost")
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err = os.WriteFile(caFile, b.Original["postgres/postgres-ca.pem"], 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Database{CAFile: caFile, TLSMode: "cloudsql-instance-ca", CloudSQLInstance: b.Input.SQLInstance, InstanceCAPEMSHA256: b.Input.PostgresCA.SHA256}
	tc, err := postgres.VerifiedTLSConfig(cfg, "10.203.11.11")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b.Original["postgres/server.pem"])
	leaf, _ := x509.ParseCertificate(block.Bytes)
	if err = tc.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}); err != nil {
		t.Fatal(err)
	}
}
func TestProtectedFinalizationExactlyOnceAndNeverAfterEnrollment(t *testing.T) {
	for _, enrolled := range []bool{false, true} {
		t.Run(map[bool]string{false: "once", true: "enrolled"}[enrolled], func(t *testing.T) {
			p, files := syntheticOriginal(t)
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			_ = os.Chmod(root, 0700)
			original := filepath.Join(root, "original-seed")
			for path, raw := range files {
				dest := filepath.Join(original, path)
				if err = mkdirPrivate(filepath.Dir(dest)); err != nil {
					t.Fatal(err)
				}
				if err = writeExclusive(dest, raw); err != nil {
					t.Fatal(err)
				}
			}
			if enrolled {
				if err = writeExclusive(filepath.Join(root, "enrollment.json"), []byte(`{}`)); err != nil {
					t.Fatal(err)
				}
				if finalizeDirectory(root, p, false) == nil {
					t.Fatal("pinned enrollment modified")
				}
				return
			}
			if err = finalizeDirectory(root, p, true); err != nil {
				t.Fatal(err)
			}
			if _, err = os.Stat(filepath.Join(root, "assembly-finalization.lock")); !os.IsNotExist(err) {
				t.Fatal("dry run mutated")
			}
			if err = finalizeDirectory(root, p, false); err != nil {
				t.Fatal(err)
			}
			before, err := readPrivate(filepath.Join(original, "assembly-input.json"))
			if err != nil {
				t.Fatal(err)
			}
			if finalizeDirectory(root, p, false) == nil {
				t.Fatal("finalized inputs refreshed")
			}
			after, _ := readPrivate(filepath.Join(original, "assembly-input.json"))
			if !bytes.Equal(before, after) {
				t.Fatal("finalized receipt changed")
			}
			for _, path := range []string{"source/etc/freeradius/3.0/device-policy-cache.json", "source/var/lib/cloud-8021x/certificate-state.json", "spec.json"} {
				actual, _ := readPrivate(filepath.Join(original, path))
				if !bytes.Equal(actual, files[path]) {
					t.Fatal("source observation changed")
				}
			}
		})
	}
}
func TestPrivateReaderRejectsLinksAndPublicFiles(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	_ = os.Chmod(root, 0700)
	path := filepath.Join(root, "secret")
	if err := writeExclusive(path, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivate(filepath.Join(root, "link")); err == nil {
		t.Fatal("symlink accepted")
	}
	_ = os.Chmod(path, 0644)
	if _, err := readPrivate(path); err == nil {
		t.Fatal("public secret accepted")
	}
}
