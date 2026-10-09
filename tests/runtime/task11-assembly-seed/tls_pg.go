package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-assembly-seed/contract"
)

func randomText() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}
func tlsIdentity(names []string, ips []net.IP, at time.Time) (ca, cert, key []byte, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return
	}
	parent := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Task11 private synthetic TLS CA"}, NotBefore: at.Add(-time.Hour), NotAfter: at.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}
	raw, err := x509.CreateCertificate(rand.Reader, parent, parent, caKey.Public(), caKey)
	if err != nil {
		return
	}
	ca = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
	serial, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return
	}
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Task11 synthetic server"}, DNSNames: names, IPAddresses: ips, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(90 * 24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	raw, err = x509.CreateCertificate(rand.Reader, leaf, parent, leafKey.Public(), caKey)
	if err != nil {
		return
	}
	cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
	raw, err = x509.MarshalPKCS8PrivateKey(leafKey)
	if err == nil {
		key = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})
	}
	return
}
func caPassword(dsn, db string) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme != "postgresql" || u.Hostname() != "10.203.11.11" || (u.Port() != "" && u.Port() != "5432") || u.Path != "/"+db || u.User == nil || u.User.Username() != "stepca" || u.Fragment != "" {
		return "", errors.New("preserved CA DSN identity differs")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", errors.New("malformed preserved CA DSN query")
	}
	if q.Get("sslmode") != "verify-full" {
		return "", errors.New("preserved CA TLS mode differs")
	}
	for name, values := range q {
		if len(values) != 1 || (name != "sslmode" && name != "sslrootcert") {
			return "", errors.New("unapproved CA DSN option")
		}
	}
	if p := q.Get("sslrootcert"); p != "/etc/cloud-8021x/postgres-ca.pem" {
		return "", errors.New("CA TLS root path differs")
	}
	password, ok := u.User.Password()
	if !ok || len(password) < 8 || len(password) > 128 || strings.ContainsAny(password, "\r\n\x00") {
		return "", errors.New("private CA password invalid")
	}
	return password, nil
}
func pgDSN(database, role, password string) string {
	u := url.URL{Scheme: "postgresql", User: url.UserPassword(role, password), Host: "10.203.11.11:5432", Path: "/" + database, RawQuery: "sslmode=verify-full"}
	return u.String()
}
func sqlLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
func postgresFiles(s seedSpec, values map[string][]byte) (map[string][]byte, error) {
	ec, err := caPassword(s.ECDB, "stepca")
	if err != nil {
		return nil, err
	}
	rsa, err := caPassword(s.RSADB, "stepca_rsa")
	if err != nil || ec != rsa {
		return nil, errors.New("shared preserved stepca user requires exact same password")
	}
	ca, cert, key, err := tlsIdentity(nil, []net.IP{net.ParseIP("10.203.11.11")}, s.ObservedAt)
	if err != nil {
		return nil, err
	}
	var sql strings.Builder
	sql.WriteString("\\set ON_ERROR_STOP on\nSET standard_conforming_strings = on;\n")
	fmt.Fprintf(&sql, "CREATE ROLE stepca LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 20 PASSWORD %s;\n", sqlLiteral(ec))
	for _, db := range []string{"stepca", "stepca_rsa"} {
		fmt.Fprintf(&sql, "CREATE DATABASE %s OWNER stepca;\nREVOKE ALL ON DATABASE %s FROM PUBLIC;\n", db, db)
	}
	for _, database := range []string{contract.Database, "cloud8021x_task11_blue"} {
		for _, role := range []struct {
			suffix, id string
			limit      int
		}{{"runtime", "postgres-runtime-dsn", 16}, {"native", "postgres-native-dsn", 4}, {"migrate", "postgres-migration-dsn", 2}} {
			password, e := randomText()
			if e != nil {
				return nil, e
			}
			name := database + "_" + role.suffix
			id := role.id
			if database != "cloud8021x_task11_green" {
				id = strings.Replace(id, "postgres-", "postgres-blue-", 1)
			}
			values[id] = []byte(pgDSN(database, name, password))
			fmt.Fprintf(&sql, "CREATE ROLE %s LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT %d PASSWORD %s;\n", name, role.limit, sqlLiteral(password))
		}
		fmt.Fprintf(&sql, "CREATE DATABASE %s OWNER %s_migrate;\nREVOKE ALL ON DATABASE %s FROM PUBLIC;\nGRANT CONNECT ON DATABASE %s TO %s_runtime,%s_native;\n\\connect %s\nREVOKE ALL ON SCHEMA public FROM PUBLIC;\n", database, database, database, database, database, database, database)
	}
	hba := "local all postgres peer\n"
	for _, ip := range []string{"10.203.11.21", "10.203.11.22", "10.203.11.31", "10.203.11.32"} {
		hba += "hostssl stepca,stepca_rsa stepca " + ip + "/32 scram-sha-256\n"
	}
	for _, ip := range []string{"10.203.11.21", "10.203.11.22"} {
		hba += "hostssl " + contract.Database + " " + contract.Database + "_runtime," + contract.Database + "_native," + contract.Database + "_migrate " + ip + "/32 scram-sha-256\n"
	}
	for _, ip := range []string{"10.203.11.31", "10.203.11.32"} {
		hba += "hostssl cloud8021x_task11_blue cloud8021x_task11_blue_runtime,cloud8021x_task11_blue_native,cloud8021x_task11_blue_migrate " + ip + "/32 scram-sha-256\n"
	}
	hba += "host all all 0.0.0.0/0 reject\nhost all all ::0/0 reject\n"
	return map[string][]byte{"postgres/postgres-ca.pem": ca, "postgres/server.pem": cert, "postgres/server.key": key, "postgres/init.sql": []byte(sql.String()), "postgres/pg_hba.conf": []byte(hba), "postgres/postgresql.conf": []byte("listen_addresses = '10.203.11.11'\nport = 5432\nhba_file = '/etc/task11-postgres/pg_hba.conf'\nssl = on\nssl_cert_file = '/etc/task11-postgres/server.pem'\nssl_key_file = '/etc/task11-postgres/server.key'\npassword_encryption = 'scram-sha-256'\nmax_connections = 100\nsuperuser_reserved_connections = 3\nfsync = on\nfull_page_writes = on\nsynchronous_commit = on\nwal_level = replica\n")}, nil
}
