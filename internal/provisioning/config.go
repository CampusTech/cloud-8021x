package provisioning

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
	"github.com/jackc/pgx/v5"
)

type Config struct {
	Host                string                 `json:"host"`
	Port                uint16                 `json:"port"`
	Administrator       string                 `json:"administrator"`
	CAFile              string                 `json:"ca_file"`
	TLSMode             string                 `json:"tls_mode"`
	Instance            string                 `json:"instance"`
	CAPin               string                 `json:"ca_pin"`
	RuntimeLimit        int                    `json:"runtime_limit"`
	NativeLimit         int                    `json:"native_limit"`
	MigrationLimit      int                    `json:"migration_limit"`
	ReservedConnections int                    `json:"reserved_connections"`
	ExpectedCA          map[string]DatabaseACL `json:"expected_ca"`
	ApprovedCAAccess    map[string][]Access    `json:"approved_ca_access"`
}

func Decode(data []byte) (Config, error) {
	var c Config
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.DisallowUnknownFields()
	if len(data) > 65536 || d.Decode(&c) != nil {
		return c, errors.New("invalid bounded administrator configuration")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("trailing administrator configuration")
	}
	return c, c.validate()
}
func (c Config) validate() error {
	ip := net.ParseIP(c.Host)
	if (c.Host != "localhost" && (ip == nil || (!ip.IsPrivate() && !ip.IsLoopback()))) || c.Port == 0 || c.Administrator == "" || strings.HasPrefix(c.Administrator, "cloud8021x_") {
		return errors.New("private administrator connection required")
	}
	if c.RuntimeLimit < 2 || c.RuntimeLimit > 128 || c.NativeLimit != 4 || c.MigrationLimit < 1 || c.MigrationLimit > 128 || c.ReservedConnections < 20 {
		return errors.New("invalid two-node connection budget")
	}
	if len(c.ExpectedCA) != 2 || len(c.ApprovedCAAccess) != 2 {
		return errors.New("exact two CA database inventories required")
	}
	for _, name := range []string{"stepca", "stepca_rsa"} {
		acl, ok := c.ExpectedCA[name]
		if !ok {
			return errors.New("fixed CA inventory missing")
		}
		if _, e := hardenedACL(acl, c.ApprovedCAAccess[name], acl.Owner); e != nil {
			return e
		}
	}
	return nil
}
func (c Config) connection() (*pgx.ConnConfig, error) {
	if e := c.validate(); e != nil {
		return nil, e
	}
	// Parse a constant only: no arbitrary DSN parameters or caller SQL are accepted.
	p, e := pgx.ParseConfig("postgres://localhost/postgres")
	if e != nil {
		return nil, e
	}
	p.Host = c.Host
	p.Port = c.Port
	p.User = c.Administrator
	p.Password = os.Getenv("PGPASSWORD")
	if p.Password == "" {
		return nil, errors.New("private runner PGPASSWORD required")
	}
	p.Database = "postgres"
	p.Fallbacks = nil
	p.ConnectTimeout = 5 * time.Second
	p.RuntimeParams = map[string]string{"application_name": "cloud8021x-private-provisioner", "search_path": "pg_catalog", "statement_timeout": "5000", "lock_timeout": "5000"}

	trusted, e := os.ReadFile(c.CAFile)
	if e != nil {
		return nil, errors.New("administrator CA unavailable")
	}
	sum := sha256.Sum256(trusted)
	block, rest := pem.Decode(trusted)
	if hex.EncodeToString(sum[:]) != c.CAPin || block == nil || block.Type != "CERTIFICATE" || strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("exact single administrator CA PEM pin required")
	}
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil || !cert.IsCA {
		return nil, errors.New("administrator CA certificate invalid")
	}
	p.TLSConfig, e = postgres.VerifiedTLSConfig(config.Database{CAFile: c.CAFile, TLSMode: c.TLSMode, CloudSQLInstance: c.Instance, InstanceCAPEMSHA256: c.CAPin}, c.Host)
	return p, e
}
