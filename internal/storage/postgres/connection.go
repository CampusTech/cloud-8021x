// Package postgres owns shared authoritative state and transaction boundaries.
package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrUnavailable = errors.New("shared database unavailable")
var ErrUncertain = errors.New("database commit outcome uncertain; resolve using stable identity")
var instanceRE = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]:[a-z]+-[a-z]+[0-9]:[a-z][a-z0-9-]{0,97}$`)

type Store struct {
	pool            *pgxpool.Pool
	timeout         time.Duration
	transition      string
	transitionBound bool
}

func tlsConfig(c config.Database, host string) (*tls.Config, error) {
	data, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, errors.New("database CA unavailable")
	}
	roots := x509.NewCertPool()
	if c.TLSMode == "verify-full" {
		if !roots.AppendCertsFromPEM(data) || host == "" {
			return nil, errors.New("invalid database CA or hostname")
		}
		return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: host}, nil
	}
	if c.TLSMode != "cloudsql-instance-ca" || !instanceRE.MatchString(c.CloudSQLInstance) {
		return nil, errors.New("invalid database TLS mode")
	}
	pin, err := hex.DecodeString(c.InstanceCAPEMSHA256)
	sum := sha256.Sum256(data)
	if err != nil || len(pin) != 32 || !strings.EqualFold(hex.EncodeToString(sum[:]), c.InstanceCAPEMSHA256) {
		return nil, errors.New("database instance CA pin mismatch")
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("instance CA must contain exactly one certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA {
		return nil, errors.New("invalid instance CA")
	}
	roots.AddCert(cert)
	return &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, // Hostname-less per-instance CA: full chain verification is mandatory below.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("database TLS certificate absent")
			}
			intermediates := x509.NewCertPool()
			for _, cert := range cs.PeerCertificates[1:] {
				intermediates.AddCert(cert)
			}
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			if err != nil {
				return errors.New("database instance CA chain rejected")
			}
			return nil
		}}, nil
}

// VerifiedTLSConfig shares the exact database chain/pin validation with the
// private provisioning runner. It does not open a connection or grant privileges.
func VerifiedTLSConfig(c config.Database, hostname string) (*tls.Config, error) {
	return tlsConfig(c, hostname)
}

// New is lazy: configuration is checked but an unreachable database does not
// prevent constructing offline authorization services. DSNs never escape errors.
func New(ctx context.Context, dsn string, c config.Database) (*Store, error) {
	return newStore(ctx, dsn, c, false)
}

// NewMigration is reserved for the explicit privileged migration command.
func NewMigration(ctx context.Context, dsn string, c config.Database) (*Store, error) {
	return newStore(ctx, dsn, c, true)
}
func newStore(ctx context.Context, dsn string, c config.Database, privileged bool) (*Store, error) {
	if c.MaxConnections < 1 || c.MaxConnections > 64 || c.MinConnections < 0 || c.MinConnections > c.MaxConnections || c.ConnectTimeout <= 0 || c.ConnectTimeout > time.Minute || c.QueryTimeout <= 0 || c.QueryTimeout > time.Minute {
		return nil, errors.New("invalid database bounds")
	}
	p, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("invalid database connection configuration")
	}
	if strings.HasPrefix(p.ConnConfig.Host, "/") || strings.Contains(p.ConnConfig.Host, ",") {
		return nil, errors.New("database requires a single TLS host")
	}
	tc, err := tlsConfig(c, p.ConnConfig.Host)
	if err != nil {
		return nil, err
	}
	p.ConnConfig.TLSConfig = tc
	p.ConnConfig.Fallbacks = nil
	p.ConnConfig.ConnectTimeout = c.ConnectTimeout
	p.ConnConfig.RuntimeParams = map[string]string{"application_name": "cloud-8021x", "synchronous_commit": "on", "statement_timeout": durationMS(c.QueryTimeout), "lock_timeout": durationMS(c.QueryTimeout), "idle_in_transaction_session_timeout": durationMS(c.QueryTimeout)}
	p.MinConns = 0 // Neither DSN warm minimum may couple startup to PostgreSQL.
	p.MinIdleConns = 0
	p.MaxConns = int32(c.MaxConnections)
	p.MaxConnLifetime = 30 * time.Minute
	p.MaxConnIdleTime = 5 * time.Minute
	p.HealthCheckPeriod = time.Minute
	p.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		var safe bool
		if err := conn.QueryRow(ctx, `SELECT current_setting('fsync')='on' AND current_setting('full_page_writes')='on' AND current_setting('synchronous_commit')='on' AND current_setting('wal_level') IN ('replica','logical')`).Scan(&safe); err != nil || !safe {
			return errors.New("database durability rejected")
		}
		if !privileged {
			if err := conn.QueryRow(ctx, `SELECT NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls) AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid) AND NOT has_database_privilege(current_user,current_database(),'CREATE,TEMP') AND NOT has_schema_privilege(current_user,'ledger','CREATE') AND NOT has_schema_privilege(current_user,'public','CREATE') FROM pg_roles r WHERE rolname=current_user`).Scan(&safe); err != nil || !safe {
				return errors.New("database runtime role rejected")
			}
		}
		return nil
	}
	pool, err := pgxpool.NewWithConfig(ctx, p)
	if err != nil {
		return nil, ErrUnavailable
	}
	return &Store{pool: pool, timeout: c.QueryTimeout}, nil
}
func durationMS(d time.Duration) string { return fmtInt(max(1, d.Milliseconds())) }
func (s *Store) Close()                 { s.pool.Close() }
func (s *Store) bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, s.timeout)
}
func safeError(err error) error {
	if err == nil {
		return nil
	}
	var p *pgconn.PgError
	if errors.As(err, &p) {
		return errors.New("shared database operation failed (SQLSTATE " + p.Code + ")")
	}
	return ErrUnavailable
}

// ForTransition returns an immutable view that fences every worker transaction.
// The original privileged store remains available only to protected migration.
// Both views share the pool; the construction owner closes it once.
func (s *Store) ForTransition(id string) *Store {
	bound := *s
	bound.transition, bound.transitionBound = id, true
	return &bound
}
