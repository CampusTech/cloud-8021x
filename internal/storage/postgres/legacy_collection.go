package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/CampusTech/cloud-8021x/internal/adapters/fleet"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/migration"
	"github.com/jackc/pgx/v5"
)

func createLegacyCollection(ctx context.Context, tx pgx.Tx, r Roles) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS ledger.legacy_collection_guards(id text PRIMARY KEY,scope text NOT NULL,source text NOT NULL,host_id numeric(20,0) NOT NULL,host_uuid text NOT NULL,command_uuid text NOT NULL,document bytea NOT NULL,observation bytea NOT NULL,state text NOT NULL DEFAULT 'quarantine' CHECK(state IN ('quarantine','resolved')),evidence bytea,UNIQUE(source,host_uuid,command_uuid))`,
		`CREATE INDEX IF NOT EXISTS legacy_collection_scope ON ledger.legacy_collection_guards(scope,state)`,
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

func importLegacyCommandGuards(ctx context.Context, tx pgx.Tx, rawCertificates []byte) error {
	if len(rawCertificates) > 0 {
		certs, e := migration.DecodeCertificates(rawCertificates)
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
	return nil
}

type LegacyCollectionGuard struct {
	ID, Source, HostUUID, State string
	Host                        migration.LegacyCertificateHost
	Command                     migration.LegacyCommand
}

func (s *Store) LegacyCollectionGuard(ctx context.Context, id string) (LegacyCollectionGuard, error) {
	out := LegacyCollectionGuard{ID: id}
	if !transitionDigest.MatchString(id) {
		return out, errors.New("invalid original guard ID")
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	var host, command []byte
	if e := s.pool.QueryRow(ctx, `SELECT source,host_uuid,state,observation,document FROM ledger.legacy_collection_guards WHERE id=$1`, id).Scan(&out.Source, &out.HostUUID, &out.State, &host, &command); e != nil {
		return out, safeError(e)
	}
	if domain.DecodeJSONStrict(host, &out.Host) != nil || domain.DecodeJSONStrict(command, &out.Command) != nil {
		return out, errors.New("invalid retained original guard")
	}
	return out, nil
}
func (s *Store) ResolveLegacyCollection(ctx context.Context, id string, evidence fleet.LegacyRecoveryEvidence) error {
	scope, ok := ctx.Value(maintenanceScopeKey{}).(*maintenanceScope)
	if !ok || scope.store != s || !scope.active.Load() {
		return errors.New("protected legacy recovery required")
	}
	raw, e := json.Marshal(evidence)
	if e != nil || len(raw) > 1<<20 || evidence.HostID == 0 || evidence.Outcome != "terminal" {
		return errors.New("invalid authenticated terminal evidence")
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	tx, e := s.begin(ctx)
	if e != nil {
		return safeError(e)
	}
	defer rollback(tx)
	tag, e := tx.Exec(ctx, `UPDATE ledger.legacy_collection_guards SET state='resolved',evidence=$2 WHERE id=$1 AND host_uuid=$3 AND host_id=$4 AND command_uuid=$5 AND (state='quarantine' OR evidence=$2)`, id, raw, evidence.HostUUID, evidence.HostID, evidence.CommandUUID)
	if e != nil {
		return safeError(e)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("original guard/evidence mismatch")
	}
	if e = commit(ctx, tx); e != nil {
		return ErrUncertain
	}
	return nil
}

// Proof-only recovery of an already committed resolution. No new evidence,
// submission, certificate observation or guard state is written here.
func (s *Store) LegacyCollectionResolved(ctx context.Context, id string) error {
	if !transitionDigest.MatchString(id) {
		return errors.New("invalid original guard ID")
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	var state, uuid, command string
	var hostID string
	var raw []byte
	if e := s.pool.QueryRow(ctx, `SELECT state,host_uuid,command_uuid,host_id::text,evidence FROM ledger.legacy_collection_guards WHERE id=$1`, id).Scan(&state, &uuid, &command, &hostID, &raw); e != nil {
		return safeError(e)
	}
	var proof fleet.LegacyRecoveryEvidence
	if state != "resolved" || len(raw) > 1<<20 || domain.DecodeJSONStrict(raw, &proof) != nil || strconv.FormatUint(proof.HostID, 10) != hostID || proof.HostUUID != uuid || proof.CommandUUID != command || proof.Outcome != "terminal" || len(proof.Response) == 0 || string(proof.Response) == "null" {
		return errors.New("exact retained terminal resolution not proven")
	}
	return nil
}
