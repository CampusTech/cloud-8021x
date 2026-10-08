package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/adapters/fleet"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/jackc/pgx/v5"
)

type OperatorRecoveryRequest struct {
	AcceptPossibleDuplicates                                               bool
	Transition, Node, ConfigSHA256, RequestID, WorkID, PayloadSHA256, Mode string
	Generation                                                             int64
}
type OperatorRecovery struct {
	Attempt  int64
	Outcome  string
	Original WorkState
	Receipt  json.RawMessage
}

// OperatorWorkArchive preserves exact PG payload/receipt bytes through JSONB
// journals and protected file archives rather than reparsing their JSON numbers.
type operatorWorkArchive struct {
	State, Owner     string
	Generation       int64
	Payload, Receipt []byte
}

func OperatorWorkArchive(w WorkState) []byte {
	raw, _ := json.Marshal(operatorWorkArchive{w.State, w.Owner, w.Generation, w.Payload, w.Receipt})
	return raw
}
func decodeOperatorWork(raw []byte, w *WorkState) error {
	var a operatorWorkArchive
	if e := domain.DecodeJSONStrict(raw, &a); e != nil {
		return e
	}
	*w = WorkState{State: a.State, Owner: a.Owner, Generation: a.Generation, Payload: a.Payload, Receipt: a.Receipt}
	return nil
}
func (r OperatorRecoveryRequest) validate() error {
	if !transitionDigest.MatchString(r.Transition) || !transitionDigest.MatchString(r.ConfigSHA256) || !transitionDigest.MatchString(r.RequestID) || !transitionDigest.MatchString(r.PayloadSHA256) || (r.Node != "radius-primary" && r.Node != "radius-secondary") || r.WorkID == "" || len(r.WorkID) > 512 || r.Generation < 1 || (r.Mode == "outbox-republish" && !r.AcceptPossibleDuplicates) || (r.Mode != "outbox-republish" && r.Mode != "fleet-terminal") {
		return errors.New("invalid exact operator recovery")
	}
	return nil
}
func (r OperatorRecoveryRequest) operation() string { return "work-recovery:" + r.RequestID }

// OperatorRecovery is a root-private exact request lookup. No row means only
// that this operator request has not started; it says nothing about delivery.
func (s *Store) OperatorRecovery(ctx context.Context, r OperatorRecoveryRequest) (OperatorRecovery, error) {
	var out OperatorRecovery
	if e := r.validate(); e != nil {
		return out, e
	}
	raw, _ := json.Marshal(r)
	var original []byte
	var matches bool
	e := s.pool.QueryRow(ctx, `SELECT request=$2::jsonb,attempt,original,coalesce(o.outcome,'started'),o.receipt FROM bootstrap_private.operator_recovery r LEFT JOIN bootstrap_private.operator_recovery_outcomes o USING(request_id) WHERE request_id=$1`, r.RequestID, raw).Scan(&matches, &out.Attempt, &original, &out.Outcome, &out.Receipt)
	if errors.Is(e, pgx.ErrNoRows) {
		return out, pgx.ErrNoRows
	}
	if e != nil {
		return out, safeError(e)
	}
	if !matches || decodeOperatorWork(original, &out.Original) != nil {
		return out, errors.New("original operator request differs")
	}
	return out, nil
}
func (s *Store) operatorScope(ctx context.Context, r OperatorRecoveryRequest) (int64, error) {
	if e := r.validate(); e != nil {
		return 0, e
	}
	scope, ok := ctx.Value(maintenanceScopeKey{}).(*maintenanceScope)
	if !ok || scope.store != s || !scope.active.Load() {
		return 0, errors.New("protected operator recovery required")
	}
	var valid bool
	if e := s.pool.QueryRow(ctx, `SELECT operation=$2 AND outcome='started' AND expires_at>clock_timestamp() FROM bootstrap_private.maintenance WHERE id=$1`, scope.id, r.operation()).Scan(&valid); e != nil || !valid {
		return 0, errors.New("exact live operator attempt required")
	}
	if e := s.operatorFence(ctx, r); e != nil {
		return 0, e
	}
	return scope.id, nil
}
func (s *Store) operatorFence(ctx context.Context, r OperatorRecoveryRequest) error {
	var valid bool
	if e := s.RequireWorkerExportReady(ctx, r.Transition); e != nil {
		return e
	}
	if e := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bootstrap_private.worker_fences f JOIN bootstrap_private.writer_fences w USING(transition,node) WHERE f.transition=$1 AND f.node=$2 AND (w.config_sha256=$3 OR EXISTS(SELECT 1 FROM bootstrap_private.writer_bindings b WHERE b.transition=w.transition AND b.node=w.node AND b.config_sha256=$3 AND b.receipt_sha256=w.receipt_sha256)))`, r.Transition, r.Node, r.ConfigSHA256).Scan(&valid); e != nil || !valid {
		return errors.New("operator config/fence differs")
	}
	return nil
}
func (s *Store) StartOperatorRecovery(ctx context.Context, r OperatorRecoveryRequest) (OperatorRecovery, error) {
	var out OperatorRecovery
	attempt, e := s.operatorScope(ctx, r)
	if e != nil {
		return out, e
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return out, safeError(e)
	}
	defer rollback(tx)
	var kind string
	var w WorkState
	e = tx.QueryRow(ctx, `SELECT kind,state,generation,coalesce(owner,''),payload,receipt FROM ledger.work WHERE id=$1 FOR UPDATE`, r.WorkID).Scan(&kind, &w.State, &w.Generation, &w.Owner, &w.Payload, &w.Receipt)
	if e != nil {
		return out, safeError(e)
	}
	hash := sha256.Sum256(w.Payload)
	if w.Generation != r.Generation || hex.EncodeToString(hash[:]) != r.PayloadSHA256 || (r.Mode == "outbox-republish" && kind != "outbox") || (r.Mode == "fleet-terminal" && (!strings.HasPrefix(kind, "fleet-cert:") || !strings.HasPrefix(r.WorkID, "fleet-cert:"))) {
		return out, errors.New("original work/generation/payload differs")
	}
	// A pending/leased record has no proven original external attempt to recover.
	if w.State != "started" && w.State != "quarantine" && w.State != "succeeded" {
		return out, errors.New("original work has no external attempt")
	}
	if r.Mode == "fleet-terminal" && w.State == "succeeded" {
		var receipt struct {
			Pending bool `json:"pending"`
		}
		if json.Unmarshal(w.Receipt, &receipt) != nil || !receipt.Pending {
			return out, errors.New("collection already terminal; original observation retained")
		}
	}
	raw, _ := json.Marshal(r)
	original := OperatorWorkArchive(w)
	tag, e := tx.Exec(ctx, `INSERT INTO bootstrap_private.operator_recovery(request_id,request,attempt,original) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, r.RequestID, raw, attempt, original)
	if e != nil {
		return out, safeError(e)
	}
	if tag.RowsAffected() != 1 {
		return out, errors.New("operator request already retained; inspect original outcome")
	}
	if e = commit(ctx, tx); e != nil {
		return out, ErrUncertain
	}
	return OperatorRecovery{Attempt: attempt, Outcome: "started", Original: w}, nil
}

// FinishOperatorRecovery appends the operator outcome. Original delivery work is
// immutable; Fleet settlement preserves its old receipt in the immutable original.
func (s *Store) FinishOperatorRecovery(ctx context.Context, r OperatorRecoveryRequest, outcome string, receipt json.RawMessage) error {
	attempt, e := s.operatorScope(ctx, r)
	if e != nil {
		return e
	}
	if len(receipt) > 1<<20 || !json.Valid(receipt) || string(receipt) == "null" {
		return errors.New("invalid operator receipt")
	}
	if r.Mode == "outbox-republish" {
		if outcome != "succeeded" && outcome != "uncertain" && outcome != "partial" && outcome != "rejected" {
			return errors.New("invalid delivery outcome")
		}
	} else {
		return errors.New("fleet requires authenticated terminal evidence")
	}
	return s.finishOperator(ctx, r, attempt, outcome, receipt, nil)
}
func (s *Store) FinishFleetRecovery(ctx context.Context, r OperatorRecoveryRequest, proof fleet.LegacyRecoveryEvidence) error {
	attempt, e := s.operatorScope(ctx, r)
	if e != nil {
		return e
	}
	if r.Mode != "fleet-terminal" || proof.Outcome != "terminal" || proof.HostID == 0 || len(proof.Response) == 0 {
		return errors.New("exact authenticated Fleet terminal required")
	}
	raw, e := json.Marshal(proof)
	if e != nil || len(raw) > 1<<20 {
		return errors.New("fleet evidence exceeds bound")
	}
	return s.finishOperator(ctx, r, attempt, "terminal", raw, &proof)
}
func (s *Store) finishOperator(ctx context.Context, r OperatorRecoveryRequest, attempt int64, outcome string, receipt json.RawMessage, proof *fleet.LegacyRecoveryEvidence) error {
	tx, e := s.begin(ctx)
	if e != nil {
		return safeError(e)
	}
	defer rollback(tx)
	raw, _ := json.Marshal(r)
	var original []byte
	if e = tx.QueryRow(ctx, `SELECT original FROM bootstrap_private.operator_recovery WHERE request_id=$1 AND request=$2::jsonb AND attempt=$3 FOR UPDATE`, r.RequestID, raw, attempt).Scan(&original); e != nil {
		return safeError(e)
	}
	if proof != nil {
		var w WorkState
		if decodeOperatorWork(original, &w) != nil {
			return errors.New("invalid original Fleet state")
		}
		var binding struct {
			HostID   uint64 `json:"host_id"`
			HostUUID string `json:"host_uuid"`
			Command  string `json:"command_uuid"`
		}
		if json.Unmarshal(w.Payload, &binding) != nil || binding.HostID != proof.HostID || binding.HostUUID != proof.HostUUID || binding.Command != proof.CommandUUID {
			return errors.New("terminal evidence escaped original work")
		}
		tag, e := tx.Exec(ctx, `UPDATE ledger.work SET state='succeeded',receipt='{"pending":false}'::jsonb,updated_at=clock_timestamp() WHERE id=$1 AND generation=$2 AND payload=$3::jsonb AND state=$4 AND receipt IS NOT DISTINCT FROM $5::jsonb`, r.WorkID, r.Generation, []byte(w.Payload), w.State, []byte(w.Receipt))
		if e != nil {
			return safeError(e)
		}
		if tag.RowsAffected() != 1 {
			return errors.New("original Fleet work changed")
		}
	}
	tag, e := tx.Exec(ctx, `INSERT INTO bootstrap_private.operator_recovery_outcomes(request_id,outcome,receipt) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, r.RequestID, outcome, []byte(receipt))
	if e != nil {
		return safeError(e)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("original operator outcome already retained")
	}
	if e = commit(ctx, tx); e != nil {
		return ErrUncertain
	}
	return nil
}

// RecoverOperatorAttempt never sends. The fixed root helper verifies original
// PID/start and flock before this call. Expiry alone is not that proof. A stopped
// attempt with no stored outcome is retained as unknown, never external success.
func (s *Store) RecoverOperatorAttempt(ctx context.Context, r OperatorRecoveryRequest, attempt int64, proveStopped func() ([]byte, error)) error {
	if e := r.validate(); e != nil {
		return e
	}
	if proveStopped == nil {
		return errors.New("original helper proof required")
	}
	if e := s.operatorFence(ctx, r); e != nil {
		return e
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return safeError(e)
	}
	defer rollback(tx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(8021,8)"); e != nil {
		return safeError(e)
	}
	var operation string
	if e = tx.QueryRow(ctx, `SELECT operation FROM bootstrap_private.maintenance WHERE id=$1 AND outcome IN ('started','uncertain') AND expires_at<clock_timestamp() FOR UPDATE`, attempt).Scan(&operation); e != nil || operation != r.operation() {
		return errors.New("exact expired original operator attempt required")
	}
	var other bool
	if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bootstrap_private.maintenance WHERE id!=$1 AND outcome IN ('started','uncertain'))`, attempt).Scan(&other); e != nil || other {
		return errors.New("another root operation remains unresolved")
	}

	protectedOriginal, e := proveStopped()
	if e != nil {
		return e
	}
	var original WorkState
	if len(protectedOriginal) > 2<<20 || decodeOperatorWork(protectedOriginal, &original) != nil {
		return errors.New("protected original work unavailable")
	}
	digest := sha256.Sum256(original.Payload)
	if original.Generation != r.Generation || hex.EncodeToString(digest[:]) != r.PayloadSHA256 {
		return errors.New("protected original work binding differs")
	}
	var saved, retained []byte
	var savedAttempt int64
	e = tx.QueryRow(ctx, `SELECT request,attempt,original FROM bootstrap_private.operator_recovery WHERE request_id=$1 FOR UPDATE`, r.RequestID).Scan(&saved, &savedAttempt, &retained)
	disposition := "uncertain"
	code := "original_helper_exited_without_durable_result"
	if errors.Is(e, pgx.ErrNoRows) {
		// This is a primary-transaction absence observation of the new operator row,
		// never evidence that the original external delivery was absent.
		var kind string
		var current WorkState
		if e = tx.QueryRow(ctx, `SELECT kind,state,generation,coalesce(owner,''),payload,receipt FROM ledger.work WHERE id=$1 FOR UPDATE`, r.WorkID).Scan(&kind, &current.State, &current.Generation, &current.Owner, &current.Payload, &current.Receipt); e != nil {
			return safeError(e)
		}
		if !reflect.DeepEqual(current, original) || (r.Mode == "outbox-republish" && kind != "outbox") || (r.Mode == "fleet-terminal" && !strings.HasPrefix(kind, "fleet-cert:")) {
			return errors.New("original work changed before pre-send proof")
		}
		raw, _ := json.Marshal(r)
		if _, e = tx.Exec(ctx, `INSERT INTO bootstrap_private.operator_recovery(request_id,request,attempt,original) VALUES($1,$2,$3,$4)`, r.RequestID, raw, attempt, protectedOriginal); e != nil {
			return safeError(e)
		}
		disposition = "no_send_proven"
		code = "new_operator_attempt_not_started_original_delivery_unknown"
	} else if e != nil {
		return safeError(e)
	} else {
		var parsed OperatorRecoveryRequest
		var prior WorkState
		if domain.DecodeJSONStrict(saved, &parsed) != nil || parsed != r || savedAttempt != attempt || decodeOperatorWork(retained, &prior) != nil || !reflect.DeepEqual(prior, original) {
			return errors.New("original operator request/work differs")
		}
	}
	receipt, _ := json.Marshal(map[string]string{"outcome": disposition, "code": code})
	if _, e = tx.Exec(ctx, `INSERT INTO bootstrap_private.operator_recovery_outcomes(request_id,outcome,receipt) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, r.RequestID, disposition, receipt); e != nil {
		return safeError(e)
	}

	if _, e = tx.Exec(ctx, `UPDATE bootstrap_private.maintenance SET outcome='reconciled',finished_at=clock_timestamp() WHERE id=$1`, attempt); e != nil {
		return safeError(e)
	}
	if _, e = tx.Exec(ctx, `INSERT INTO bootstrap_private.maintenance_recoveries(attempt,operation) VALUES($1,$2)`, attempt, operation); e != nil {
		return safeError(e)
	}
	if e = commit(ctx, tx); e != nil {
		return ErrUncertain
	}
	return nil
}

// OperatorMaintenanceAttempt binds the local original helper before any send.
func (s *Store) OperatorMaintenanceAttempt(ctx context.Context, r OperatorRecoveryRequest) (int64, error) {
	return s.operatorScope(ctx, r)
}

// OriginalOutboxSucceeded proves only a retained original local PG outcome. It
// cannot prove delivery beyond the Collector and never changes work state.
func (s *Store) OriginalOutboxSucceeded(ctx context.Context, id string, generation int64, hash string) error {
	if id == "" || generation < 1 || !transitionDigest.MatchString(hash) {
		return errors.New("exact original outbox required")
	}
	var kind string
	if e := s.pool.QueryRow(ctx, `SELECT kind FROM ledger.work WHERE id=$1`, id).Scan(&kind); e != nil {
		return safeError(e)
	}
	w, e := s.LookupWork(ctx, id)
	if e != nil {
		return e
	}
	digest := sha256.Sum256(w.Payload)
	var receipt struct {
		Outcome  string `json:"outcome"`
		Code     string `json:"code"`
		Rejected int64  `json:"rejected,omitempty"`
	}
	if kind != "outbox" || w.State != "succeeded" || w.Generation != generation || hex.EncodeToString(digest[:]) != hash || domain.DecodeJSONStrict(w.Receipt, &receipt) != nil || receipt.Outcome != "succeeded" || receipt.Rejected != 0 || receipt.Code == "" {
		return errors.New("exact committed original outbox success not proven")
	}
	return nil
}
