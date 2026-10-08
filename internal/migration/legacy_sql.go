package migration

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

// SnapshotLegacySQL accepts only the fixed connector constructed by the root
// host adapter. It never changes a row, schema, global variable, or DB service.
func SnapshotLegacySQL(ctx context.Context, connector driver.Connector) (LegacySQL, error) {
	out := LegacySQL{Status: "exported", Rows: []LegacySQLRow{}}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	defer func() { _ = db.Close() }()
	tx, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if e != nil {
		return out, errors.New("legacy SQL read-only snapshot unavailable")
	}
	defer func() { _ = tx.Rollback() }()
	if e = tx.QueryRowContext(ctx, `SELECT @@session.time_zone,@@system_time_zone,@@version`).Scan(&out.SessionTimeZone, &out.SystemTimeZone, &out.ServerVersion); e != nil {
		return out, errors.New("legacy SQL timezone evidence unavailable")
	}
	rows, e := tx.QueryContext(ctx, `SELECT radacctid,acctuniqueid,acctsessionid,username,nasipaddress,callingstationid,calledstationid,CAST(acctstarttime AS CHAR),CAST(acctupdatetime AS CHAR),CAST(acctstoptime AS CHAR),acctsessiontime,acctinputoctets,acctoutputoctets,acctterminatecause FROM radius.radacct ORDER BY radacctid LIMIT 100001`)
	if e != nil {
		return out, errors.New("fixed legacy radacct projection unavailable")
	}
	defer func() { _ = rows.Close() }()
	total := 0
	for rows.Next() {
		if len(out.Rows) >= 100000 {
			return out, errors.New("legacy SQL row bound exceeded")
		}
		var r LegacySQLRow
		var id string
		var start, update, stop, duration, input, output sql.NullString
		if e = rows.Scan(&id, &r.UniqueID, &r.SessionID, &r.Username, &r.NASAddress, &r.CallingStation, &r.CalledStation, &start, &update, &stop, &duration, &input, &output, &r.TerminateCause); e != nil {
			return out, errors.New("legacy SQL projection schema mismatch")
		}
		r.ID, e = strconv.ParseUint(id, 10, 64)
		if e != nil {
			return out, errors.New("invalid original SQL identifier")
		}
		for _, pair := range []struct {
			raw    sql.NullString
			target **string
		}{{start, &r.Start}, {update, &r.Update}, {stop, &r.Stop}} {
			if pair.raw.Valid {
				v := pair.raw.String
				*pair.target = &v
			}
		}
		for _, pair := range []struct {
			raw    sql.NullString
			target **uint64
		}{{duration, &r.Duration}, {input, &r.Input}, {output, &r.Output}} {
			if pair.raw.Valid {
				v, e := strconv.ParseUint(pair.raw.String, 10, 64)
				if e != nil {
					return out, errors.New("invalid original SQL unsigned counter")
				}
				*pair.target = &v
			}
		}
		raw, e := json.Marshal(r)
		if e != nil {
			return out, e
		}
		total += len(raw)
		if total > 48<<20 {
			return out, errors.New("legacy SQL byte bound exceeded")
		}
		out.Rows = append(out.Rows, r)
	}
	if e = rows.Err(); e != nil {
		return out, errors.New("legacy SQL snapshot interrupted")
	}
	if e = rows.Close(); e != nil {
		return out, e
	}
	if e = validateSQL(out); e != nil {
		return out, e
	}
	// A successful read-only rollback closes the snapshot without committing any mutation.
	if e = tx.Rollback(); e != nil {
		return out, errors.New("legacy SQL snapshot completion unknown")
	}
	return out, nil
}
