package postgres

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestNativeConninfoPreservesVerifiedTLSAndIgnoresDSNOverrides(t *testing.T) {
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
	if e != nil {
		t.Fatal(e)
	}
	c := config.Defaults().Database
	c.CAFile = filepath.Join(t.TempDir(), "ca.pem")
	if e = os.WriteFile(c.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
		t.Fatal(e)
	}
	t.Run("incoming-public-trust-before-installed-file", func(t *testing.T) {
		incoming := c
		incoming.CAFile = "/etc/cloud-8021x/postgres-ca.pem"
		incoming.InstanceCAPEMSHA256 = pinFile(t, c.CAFile)
		ca, err := os.ReadFile(c.CAFile)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := NativeConninfoWithCA("postgres://native:fixture@localhost/cloud8021x", incoming, ca)
		if err != nil || !strings.Contains(conn, "sslrootcert='/etc/cloud-8021x/postgres-ca.pem'") {
			t.Fatal("incoming trust validation did not retain installed path", err)
		}
		if _, err := NativeConninfoWithCA("postgres://native:fixture@localhost/cloud8021x", incoming, append(ca, '\n')); err == nil {
			t.Fatal("changed incoming trust accepted")
		}
	})
	dsn := `host=localhost port=5432 dbname=cloud8021x user=native password='quote\'slash\\' sslmode=disable options='-c synchronous_commit=off' connect_timeout=999`
	rendered, e := NativeConninfo(dsn, c)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := pgconn.ParseConfig(rendered)
	if e != nil {
		t.Fatal(e)
	}
	if parsed.Password != "quote'slash\\" || parsed.TLSConfig == nil || parsed.TLSConfig.InsecureSkipVerify || strings.Contains(rendered, "synchronous_commit=off") || strings.Contains(rendered, "connect_timeout=999") {
		t.Fatal("unsafe reconstructed native configuration")
	}
	c.TLSMode = "cloudsql-instance-ca"
	c.CloudSQLInstance = "campus-test:us-central1:isolated-test"
	c.InstanceCAPEMSHA256 = pinFile(t, c.CAFile)
	rendered, e = NativeConninfo(dsn, c)
	if e != nil || !strings.Contains(rendered, "sslmode=verify-ca") {
		t.Fatal("explicit pinned instance mode", e)
	}
	c.InstanceCAPEMSHA256 = strings.Repeat("0", 64)
	if _, e = NativeConninfo(dsn, c); e == nil {
		t.Fatal("accepted wrong instance pin")
	}
	c.TLSMode = "disable"
	if _, e = NativeConninfo(dsn, c); e == nil {
		t.Fatal("accepted unverified native TLS")
	}
}
