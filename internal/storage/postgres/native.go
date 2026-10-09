package postgres

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/jackc/pgx/v5/pgconn"
)

// NativeConninfo applies exactly the same CA/pin gate as pgx, then emits a
// bounded libpq keyword connection string, discarding DSN-supplied options.
// Instance-CA mode still requires Task8 root attestation of the configured pin.
func NativeConninfo(dsn string, c config.Database) (string, error) {
	data, err := os.ReadFile(c.CAFile)
	if err != nil {
		return "", errors.New("database CA unavailable")
	}
	return NativeConninfoWithCA(dsn, c, data)
}

// NativeConninfoWithCA validates a protected incoming PEM while retaining the
// final installed path in libpq configuration. It uses the same TLS/pin gate.
func NativeConninfoWithCA(dsn string, c config.Database, data []byte) (string, error) {
	p, e := pgconn.ParseConfig(dsn)
	if e != nil || p.Database != "cloud8021x" || p.Host == "" || strings.HasPrefix(p.Host, "/") || strings.Contains(p.Host, ",") {
		return "", errors.New("invalid native database configuration")
	}
	if _, e = tlsConfigFromPEM(c, p.Host, data); e != nil {
		return "", e
	}
	if c.ConnectTimeout <= 0 || c.ConnectTimeout.Seconds() > 60 || c.QueryTimeout <= 0 || c.QueryTimeout.Seconds() > 60 {
		return "", errors.New("invalid native database timeouts")
	}
	q := func(s string) (string, error) {
		if strings.ContainsAny(s, "\x00\r\n%$`") {
			return "", errors.New("unsupported native connection characters")
		}
		return "'" + strings.NewReplacer("\\", "\\\\", "'", "\\'").Replace(s) + "'", nil
	}
	mode := "verify-full"
	if c.TLSMode == "cloudsql-instance-ca" {
		mode = "verify-ca"
	}
	out := "sslmode=" + mode + " port=" + strconv.Itoa(int(p.Port)) + " connect_timeout=" + strconv.Itoa(max(1, int(c.ConnectTimeout.Seconds())))
	for _, v := range []struct{ k, v string }{{"host", p.Host}, {"dbname", p.Database}, {"user", p.User}, {"password", p.Password}, {"sslrootcert", c.CAFile}, {"application_name", "cloud8021x-native"}, {"options", fmt.Sprintf("-c statement_timeout=%d -c lock_timeout=%d -c synchronous_commit=on", c.QueryTimeout.Milliseconds(), c.QueryTimeout.Milliseconds())}} {
		value, e := q(v.v)
		if e != nil {
			return "", e
		}
		out += " " + v.k + "=" + value
	}
	return out, nil
}
