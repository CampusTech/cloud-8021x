package provisioning

import (
	"context"
	"errors"
	"reflect"
	"strconv"

	"github.com/jackc/pgx/v5"
)

type reader interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readCA(ctx context.Context, q reader, name string) (DatabaseACL, error) {
	var acl DatabaseACL
	if name != "stepca" && name != "stepca_rsa" {
		return acl, errors.New("unapproved CA database")
	}
	if e := q.QueryRow(ctx, `SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=$1`, name).Scan(&acl.Owner); e != nil {
		return acl, errors.New("CA database owner unavailable")
	}
	rows, e := q.Query(ctx, `SELECT pg_get_userbyid(a.grantor), CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END, a.privilege_type,a.is_grantable FROM pg_database d CROSS JOIN LATERAL aclexplode(coalesce(d.datacl,acldefault('d',d.datdba))) a WHERE d.datname=$1`, name)
	if e != nil {
		return acl, errors.New("CA database ACL unavailable")
	}
	defer rows.Close()
	acl.Grants = []Grant{}
	for rows.Next() {
		var g Grant
		if rows.Scan(&g.Grantor, &g.Role, &g.Privilege, &g.Grantable) != nil {
			return acl, errors.New("CA ACL decode failed")
		}
		acl.Grants = append(acl.Grants, g)
	}
	if rows.Err() != nil {
		return acl, errors.New("CA ACL read failed")
	}
	return normalizeACL(acl), nil
}
func connect(ctx context.Context, c Config) (*pgx.Conn, error) {
	p, e := c.connection()
	if e != nil {
		return nil, e
	}
	connection, e := pgx.ConnectConfig(ctx, p)
	if e != nil {
		return nil, errors.New("private administrator TLS connection failed")
	}
	return connection, nil
}
func Check(ctx context.Context, c Config) (map[string]string, error) {
	conn, e := connect(ctx, c)
	if e != nil {
		return nil, e
	}
	defer func() { _ = conn.Close(ctx) }()
	tx, e := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if e != nil {
		return nil, errors.New("administrator read-only transaction unavailable")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, name := range []string{"stepca", "stepca_rsa"} {
		actual, e := readCA(ctx, tx, name)
		if e != nil {
			return nil, e
		}
		expected, e := hardenedACL(c.ExpectedCA[name], c.ApprovedCAAccess[name], c.ExpectedCA[name].Owner)
		if e != nil {
			return nil, e
		}
		if !reflect.DeepEqual(actual, expected) {
			return nil, errors.New("CA ACL prerequisite differs from exact approved inventory; no application roles may be provisioned")
		}
		for _, access := range c.ApprovedCAAccess[name] {
			var exists bool
			if tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)", access.Role).Scan(&exists) != nil || !exists {
				return nil, errors.New("approved CA client role missing")
			}
		}
	}
	var maximum, reserved int
	var durable bool
	e = tx.QueryRow(ctx, `SELECT current_setting('max_connections')::int,current_setting('superuser_reserved_connections')::int+coalesce(current_setting('reserved_connections',true),'0')::int,current_setting('fsync')='on' AND current_setting('full_page_writes')='on' AND current_setting('synchronous_commit')='on' AND current_setting('wal_level') IN ('replica','logical')`).Scan(&maximum, &reserved, &durable)
	if e != nil || !durable {
		return nil, errors.New("database durability/capacity prerequisite unavailable")
	}
	// Provider database creation holds a transaction while issuing a second
	// connection operation. Two fixed database pools of four, plus this check.
	const administratorConnections = 9
	required := c.RuntimeLimit + c.NativeLimit + c.MigrationLimit + c.ReservedConnections + administratorConnections
	if maximum-reserved < required {
		return nil, errors.New("insufficient reserved CA and two-node application connection capacity")
	}
	database, roles, identityErr := c.applicationIdentity()
	if identityErr != nil {
		return nil, identityErr
	}
	var unsafe int
	if tx.QueryRow(ctx, `SELECT count(*) FROM pg_roles r WHERE rolname = ANY($1) AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR has_database_privilege(r.oid,'stepca','CONNECT,TEMP') OR has_database_privilege(r.oid,'stepca_rsa','CONNECT,TEMP') OR EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid) OR EXISTS(SELECT 1 FROM pg_database WHERE datdba=r.oid AND (r.rolname<>$2 OR datname<>$3)))`, roles[:], roles[2], database).Scan(&unsafe) != nil || unsafe != 0 {
		return nil, errors.New("existing application role exceeds approved privileges")
	}
	if tx.Commit(ctx) != nil {
		return nil, errors.New("administrator read-only verification did not complete")
	}
	return map[string]string{"verified": "true", "maximum_connections": strconv.Itoa(maximum), "application_connections": strconv.Itoa(required - c.ReservedConnections - administratorConnections), "reserved_ca_connections": strconv.Itoa(c.ReservedConnections), "administrator_connections": strconv.Itoa(administratorConnections)}, nil
}

// Harden is a separate explicitly invoked administrator action. A dry-run only
// reads. Apply changes fixed CA database CONNECT/TEMP ACLs in one transaction;
// it cannot create roles, change owners, inspect data, rotate passwords or touch
// schema. Exact before/after comparison refuses unknown concurrent grant drift.
func Harden(ctx context.Context, c Config, apply bool) error {
	conn, e := connect(ctx, c)
	if e != nil {
		return e
	}
	defer func() { _ = conn.Close(ctx) }()
	options := pgx.TxOptions{}
	if !apply {
		options.AccessMode = pgx.ReadOnly
	}
	tx, e := conn.BeginTx(ctx, options)
	if e != nil {
		return errors.New("CA ACL transaction unavailable")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	changes := map[string]DatabaseACL{}
	for _, name := range []string{"stepca", "stepca_rsa"} {
		original := normalizeACL(c.ExpectedCA[name])
		if original.Owner != c.Administrator {
			return errors.New("CA hardening must connect as the exact approved database owner")
		}
		expected, e := hardenedACL(original, c.ApprovedCAAccess[name], original.Owner)
		if e != nil {
			return e
		}
		actual, e := readCA(ctx, tx, name)
		if e != nil {
			return e
		}
		if reflect.DeepEqual(actual, expected) {
			continue
		}
		if !reflect.DeepEqual(actual, original) {
			return errors.New("CA ACL changed from reviewed inventory; refusing hardening")
		}
		for _, access := range c.ApprovedCAAccess[name] {
			var exists bool
			if tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)", access.Role).Scan(&exists) != nil || !exists {
				return errors.New("approved CA client role missing")
			}
		}
		changes[name] = expected
	}
	if apply {
		// Preserve required explicit access in BOTH databases before revoking PUBLIC.
		for _, name := range []string{"stepca", "stepca_rsa"} {
			expected, change := changes[name]
			if !change {
				continue
			}
			actual, e := readCA(ctx, tx, name)
			if e != nil {
				return e
			}
			for _, g := range expected.Grants {
				found := false
				for _, old := range actual.Grants {
					if old == g {
						found = true
					}
				}
				if found {
					continue
				}
				if g.Privilege != "CONNECT" && g.Privilege != "TEMPORARY" {
					return errors.New("unapproved grant change")
				}
				if _, e = tx.Exec(ctx, "GRANT "+g.Privilege+" ON DATABASE "+pgx.Identifier{name}.Sanitize()+" TO "+pgx.Identifier{g.Role}.Sanitize()); e != nil {
					return errors.New("explicit CA access preservation failed")
				}
			}
		}
		for _, name := range []string{"stepca", "stepca_rsa"} {
			if _, change := changes[name]; change {
				if _, e = tx.Exec(ctx, "REVOKE CONNECT,TEMPORARY ON DATABASE "+pgx.Identifier{name}.Sanitize()+" FROM PUBLIC"); e != nil {
					return errors.New("CA PUBLIC restriction failed")
				}
			}
		}
		for _, name := range []string{"stepca", "stepca_rsa"} {
			actual, e := readCA(ctx, tx, name)
			if e != nil {
				return e
			}
			expected, e := hardenedACL(c.ExpectedCA[name], c.ApprovedCAAccess[name], c.ExpectedCA[name].Owner)
			if e != nil {
				return e
			}
			if !reflect.DeepEqual(actual, expected) {
				return errors.New("CA ACL postcondition differs; rolling back")
			}
		}
	}
	if tx.Commit(ctx) != nil {
		return errors.New("CA ACL commit outcome unknown; run exact read-only prerequisite verification before any further action")
	}
	return nil
}
