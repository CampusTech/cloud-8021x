package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/CampusTech/cloud-8021x/internal/adapters/fleet"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/migration"
)

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
	if e != nil || len(raw) > 1<<20 || evidence.HostID == 0 || (evidence.Outcome != "terminal" && evidence.Outcome != "absent") {
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
