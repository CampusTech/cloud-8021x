package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
	seed "github.com/CampusTech/cloud-8021x/tests/runtime/task11-assembly-seed/contract"
	"gopkg.in/yaml.v3"
)

func syntheticCA(t *testing.T) ([]byte, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic PostgreSQL"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, v, v, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert, key
}
func material(t *testing.T) (plan, [][]byte) {
	t.Helper()
	ca, _, _ := syntheticCA(t)
	pin := digest(ca)
	project := "task11-acceptance"
	dsn := []byte("postgresql://" + database + "_migrate:private-password@10.203.11.11:5432/" + database + "?sslmode=verify-full")
	api, err := json.Marshal(map[string]any{"secrets": map[string]any{"projects/111222333444/secrets/postgres-blue-migration-dsn": map[string]string{"1": base64.StdEncoding.EncodeToString(dsn)}}})
	if err != nil {
		t.Fatal(err)
	}
	s := seed.Input{Schema: 1, Project: project, ProjectNumber: seed.ProjectNumber, SQLInstance: project + ":us-central1:task11-postgres", ECDNS: "ec.task11.test", RSADNS: "rsa.task11.test", ServerDNS: "radius.task11.test", ObservedAt: time.Unix(1800000000, 0).UTC(), CollectionEpoch: time.Unix(1800000001, 0).UTC(), DatadogSite: "us5.datadoghq.com", PostgresCA: seed.FilePin{Path: "postgres/postgres-ca.pem", SHA256: pin}, APICA: seed.FilePin{Path: "api/ca.pem", SHA256: strings.Repeat("a", 64)}, InstalledSeedSHA256: digest(api), OriginalManifestSHA256: strings.Repeat("b", 64), OriginalStateSHA256: strings.Repeat("c", 64), Credentials: seed.Credentials(project), SourceCredentials: seed.SourceCredentials(project), Files: map[string]string{}}
	s.Files[s.PostgresCA.Path] = pin
	s.Files[s.APICA.Path] = s.APICA.SHA256
	s.Files["api/seed.json"] = s.InstalledSeedSHA256
	s.Files["original-manifest.json"] = s.OriginalManifestSHA256
	s.Files["source/var/lib/cloud-8021x/certificate-state.json"] = s.OriginalStateSHA256
	for i := 0; i < 20; i++ {
		s.Files["synthetic-other-"+strconv.Itoa(i)] = strings.Repeat("d", 64)
	}
	c := config.Defaults()
	c.SchemaVersion = 1
	c.Hostname = "task11-blue-primary"
	c.InstanceID = "radius-primary"
	c.Environment = "task11-synthetic"
	c.Database.Name = database
	c.Database.CAFile = caPath
	c.Database.TLSMode = "cloudsql-instance-ca"
	c.Database.CloudSQLInstance = s.SQLInstance
	c.Database.InstanceCAPEMSHA256 = pin
	c.Database.RuntimeDSN = config.SecretRef{File: "/run/cloud-8021x/credentials/postgres-runtime-dsn"}
	c.Database.MigrationDSN = config.SecretRef{File: migrationDSN}
	c.Database.NativeWriterDSN = config.SecretRef{File: "/run/cloud-8021x-root/postgres-native-dsn"}
	c.Bootstrap.Project = project
	c.Bootstrap.ProjectNumber = seed.ProjectNumber
	c.Bootstrap.RuntimeRole = database + "_runtime"
	c.Bootstrap.NativeRole = database + "_native"
	c.Bootstrap.LocalAddress = "10.203.11.31"
	c.Bootstrap.PeerAddress = "10.203.11.32"
	c.Bootstrap.PeerDNS = "task11-blue-secondary"
	c.Paths.InventoryFile = "/etc/freeradius/3.0/device-policy-cache.json"
	c.Policy.ClassSigningKey = config.SecretRef{File: "/run/radius-accounting-key"}
	c.Listeners.Policy.Address = "127.0.0.1:9082"
	c.Listeners.Policy.Token = config.SecretRef{File: "/run/cloud-8021x/credentials/policy-token"}
	refs := seed.Credentials(project)
	for i, r := range refs {
		for _, b := range s.SourceCredentials {
			if r.File == b.File {
				refs[i] = b
			}
		}
	}
	for _, r := range refs {
		c.Bootstrap.Secrets = append(c.Bootstrap.Secrets, config.BootstrapSecret{Resource: r.Resource, File: r.File, Owner: r.Owner})
	}
	cfg, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	p := plan{Schema: 1, MachineID: strings.Repeat("a", 32), ConfigSHA256: digest(cfg), InputSHA256: digest(input), DSNSHA256: digest(dsn), CASHA256: pin}
	return p, [][]byte{input, cfg, api, dsn, ca}
}
func TestActualParserAndIndependentByteBindings(t *testing.T) {
	p, b := material(t)
	v, err := validateMaterial(p, b[0], b[1], b[2], b[3], b[4])
	if err != nil {
		t.Fatal(err)
	}
	if v.Config.Database.Name != database {
		t.Fatal("actual parser selected wrong DB")
	}
	for i := range b {
		copyOf := append([][]byte(nil), b...)
		copyOf[i] = append(append([]byte(nil), b[i]...), byte(' '))
		if _, err = validateMaterial(p, copyOf[0], copyOf[1], copyOf[2], copyOf[3], copyOf[4]); err == nil {
			t.Fatalf("changed input%d accepted", i)
		}
	}
	for _, mutate := range []func(*config.Config){func(c *config.Config) { c.Bootstrap.RuntimeRole = "stepca" }, func(c *config.Config) { c.Database.TLSMode = "verify-full" }, func(c *config.Config) { c.Database.CAFile = "/tmp/other.pem" }, func(c *config.Config) { c.Bootstrap.LocalAddress = "10.203.11.21" }, func(c *config.Config) { c.Database.MaxConnections = 2 }, func(c *config.Config) { c.Deployment.Mode = "parallel" }} {
		c := v.Config
		mutate(&c)
		if validateBlueConfig(c, c.Bootstrap.Project, p.CASHA256) == nil {
			t.Fatal("mutated scope accepted")
		}
	}
}
func TestShippingTLSRejectsWrongChainAndPreservesPinnedCA(t *testing.T) {
	ca, root, key := syntheticCA(t)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "synthetic database"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Minute), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, leafKey.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err = os.WriteFile(p, ca, 0600); err != nil {
		t.Fatal(err)
	}
	c := config.Defaults().Database
	c.TLSMode = "cloudsql-instance-ca"
	c.CloudSQLInstance = "task11-acceptance:us-central1:task11-postgres"
	c.CAFile = p
	c.InstanceCAPEMSHA256 = digest(ca)
	transport, err := postgres.VerifiedTLSConfig(c, "10.203.11.11")
	if err != nil {
		t.Fatal(err)
	}
	if transport.VerifyConnection == nil || transport.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}) != nil {
		t.Fatal("shipping pinned chain rejected")
	}
	_, wrong, _ := syntheticCA(t)
	if transport.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{wrong}}) == nil {
		t.Fatal("wrong chain accepted")
	}
	c.InstanceCAPEMSHA256 = strings.Repeat("a", 64)
	if _, err = postgres.VerifiedTLSConfig(c, "10.203.11.11"); err == nil {
		t.Fatal("wrong CA pin accepted")
	}
}
