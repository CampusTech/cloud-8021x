package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/CampusTech/cloud-8021x/internal/migration"
	"github.com/jackc/pgx/v5"
)

func createLegacyBundle(ctx context.Context, tx pgx.Tx, r Roles) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS bootstrap_private.legacy_bundles(transition text NOT NULL REFERENCES bootstrap_private.transitions(id),node text NOT NULL,checksum text NOT NULL,document bytea NOT NULL,published boolean NOT NULL DEFAULT false,PRIMARY KEY(transition,node))`,
		`CREATE TABLE IF NOT EXISTS ledger.legacy_collection_guards(id text PRIMARY KEY,scope text NOT NULL,source text NOT NULL,host_id numeric(20,0) NOT NULL,host_uuid text NOT NULL,command_uuid text NOT NULL,document bytea NOT NULL,observation bytea NOT NULL,state text NOT NULL DEFAULT 'quarantine' CHECK(state IN ('quarantine','resolved')),evidence bytea,UNIQUE(source,host_uuid,command_uuid))`,
		`CREATE INDEX IF NOT EXISTS legacy_collection_scope ON ledger.legacy_collection_guards(scope,state)`,
		`REVOKE ALL ON bootstrap_private.legacy_bundles FROM PUBLIC,` + pgx.Identifier{r.Runtime}.Sanitize() + `,` + pgx.Identifier{r.Native}.Sanitize(),
		`REVOKE ALL ON ledger.legacy_collection_guards FROM PUBLIC,` + pgx.Identifier{r.Runtime}.Sanitize() + `,` + pgx.Identifier{r.Native}.Sanitize(),
		`GRANT SELECT ON ledger.legacy_collection_guards TO ` + pgx.Identifier{r.Runtime}.Sanitize(),
	}
	for _, q := range queries {
		if _, e := tx.Exec(ctx, q); e != nil {
			return e
		}
	}
	return nil
}
func bundleDigest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

// ImportLegacyBundle validates every legacy domain before entering one atomic
// import callback. Local publication is acknowledged separately; no worker can
// start until BOTH nodes have committed and published their whole validated set.
func (s *Store) ImportLegacyBundle(ctx context.Context, id string, data []byte) (bool, error) {
	b, e := migration.DecodeBundle(data)
	if e != nil {
		return false, e
	}
	if e = s.RequireWriterFences(ctx, id); e != nil {
		return false, e
	}
	scope, ok := ctx.Value(maintenanceScopeKey{}).(*maintenanceScope)
	if !ok || scope.store != s || !scope.active.Load() {
		return false, errors.New("root migration scope required")
	}
	if b.FreshAbsenceSHA256 != "" {
		var ready bool
		if e = s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bootstrap_private.fresh_inventory i JOIN bootstrap_private.fresh_seeds f USING(transition,node) WHERE i.transition=$1 AND i.node=$2 AND f.checksum=$3 AND i.bundle_sha256=f.checksum AND i.config_sha256=f.config_sha256)`, id, b.Node, bundleDigest(data)).Scan(&ready); e != nil {
			return false, safeError(e)
		}
		if !ready {
			return false, errors.New("fresh initial observer authority not durably proven")
		}
	}
	checksum := bundleDigest(data)
	return s.ImportOnce(ctx, "state:"+id+":"+b.Node, checksum, func(ctx context.Context, tx pgx.Tx) error {
		var enabled, blocked bool
		if e := tx.QueryRow(ctx, `SELECT enabled,blocked FROM bootstrap_private.transitions WHERE id=$1 FOR UPDATE`, id).Scan(&enabled, &blocked); e != nil {
			return e
		}
		if enabled || blocked {
			return errors.New("legacy import requires fenced transition")
		}
		// Shared Class identity and mode cannot silently differ across nodes.
		rows, e := tx.Query(ctx, `SELECT document FROM bootstrap_private.legacy_bundles WHERE transition=$1`, id)
		if e != nil {
			return e
		}
		for rows.Next() {
			var raw []byte
			if e = rows.Scan(&raw); e != nil {
				rows.Close()
				return e
			}
			other, e := migration.DecodeBundle(raw)
			if e != nil || other.ClassKeySHA256 != b.ClassKeySHA256 || other.FingerprintEnforced != b.FingerprintEnforced {
				rows.Close()
				return errors.New("peer legacy Class/identity guard differs")
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		if !b.UsageAbsent {
			var usage []byte
			e = tx.QueryRow(ctx, `SELECT document FROM bootstrap_private.legacy_usage WHERE transition=$1`, id).Scan(&usage)
			if errors.Is(e, pgx.ErrNoRows) {
				checkpoint, e := migration.DecodeUsage(b.Usage, []string{"radius-primary", "radius-secondary"})
				if e != nil {
					return e
				}
				if e = importLegacyUsageTx(ctx, tx, id, b.Usage, []string{"radius-primary", "radius-secondary"}, checkpoint); e != nil {
					return e
				}
			} else if e != nil {
				return e
			} else if bundleDigest(usage) != bundleDigest(b.Usage) {
				return errors.New("peer usage checkpoint differs; original highwater reconciliation required")
			}
		}
		if len(b.Certificates) > 0 {
			certs, e := migration.DecodeCertificates(b.Certificates)
			if e != nil {
				return e
			}
			for _, command := range certs.Commands {
				for uuid := range command.Hosts {
					host := certs.Hosts[uuid]
					var hostID uint64
					if json.Unmarshal(host.Binding[0], &hostID) != nil {
						return errors.New("legacy host ID invalid")
					}
					raw, e := json.Marshal(command)
					if e != nil {
						return e
					}
					observation, e := json.Marshal(host)
					if e != nil {
						return e
					}
					scope := migration.LegacyCollectionScope(certs.Source, hostID, uuid)
					guard := bundleDigest([]byte(scope + "\x00" + command.UUID))
					tag, e := tx.Exec(ctx, `INSERT INTO ledger.legacy_collection_guards(id,scope,source,host_id,host_uuid,command_uuid,document,observation) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(id) DO UPDATE SET id=EXCLUDED.id WHERE legacy_collection_guards.document=EXCLUDED.document AND legacy_collection_guards.observation=EXCLUDED.observation`, guard, scope, certs.Source, strconv.FormatUint(hostID, 10), uuid, command.UUID, raw, observation)
					if e != nil {
						return e
					}
					if tag.RowsAffected() != 1 {
						return errors.New("peer pending Fleet evidence differs")
					}
				}
			}
		}
		_, e = tx.Exec(ctx, `INSERT INTO bootstrap_private.legacy_bundles(transition,node,checksum,document) VALUES($1,$2,$3,$4)`, id, b.Node, checksum, data)
		return e
	})
}
func (s *Store) ConfirmLegacyPublication(ctx context.Context, id, node, checksum string) error {
	scope, ok := ctx.Value(maintenanceScopeKey{}).(*maintenanceScope)
	if !ok || scope.store != s || !scope.active.Load() || !transitionDigest.MatchString(checksum) {
		return errors.New("root publication evidence required")
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	tx, e := s.begin(ctx)
	if e != nil {
		return safeError(e)
	}
	defer rollback(tx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(8021,2)"); e != nil {
		return safeError(e)
	}
	tag, e := tx.Exec(ctx, `UPDATE bootstrap_private.legacy_bundles SET published=true WHERE transition=$1 AND node=$2 AND checksum=$3`, id, node, checksum)
	if e != nil {
		return safeError(e)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("committed bundle does not match local publication")
	}
	var combined string
	e = tx.QueryRow(ctx, `SELECT string_agg(checksum,':' ORDER BY node) FROM bootstrap_private.legacy_bundles WHERE transition=$1 AND published HAVING count(*)=2`, id).Scan(&combined)
	if e == nil {
		if _, e = tx.Exec(ctx, `INSERT INTO ledger.import_markers(id,checksum) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET checksum=EXCLUDED.checksum WHERE import_markers.checksum=EXCLUDED.checksum`, "state:"+id, bundleDigest([]byte(combined))); e != nil {
			return safeError(e)
		}
	} else if !errors.Is(e, pgx.ErrNoRows) {
		return safeError(e)
	}
	if e = commit(ctx, tx); e != nil {
		return ErrUncertain
	}
	return nil
}
