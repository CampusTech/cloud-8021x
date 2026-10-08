package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting"
	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
	"github.com/CampusTech/cloud-8021x/internal/jobs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type ProcessResult struct {
	IntakeID                 int64
	EventID, UsageID, Reason string
	Processed                bool
}

// ProcessOne locks a queued SESSION before inspecting its raw records. The
// intake trigger creates/queues that row in the writer's transaction. Thus
// neither normalization nor SKIP LOCKED on raw rows can hide a queued Start.
func (s *Store) ProcessOne(ctx context.Context, key []byte, maxAge time.Duration) (ProcessResult, error) {
	if len(key) < 32 || maxAge <= 0 || maxAge > binding.MaxAge {
		return ProcessResult{}, errors.New("invalid accounting binding configuration")
	}
	for attempt := 0; attempt < 3; attempt++ {
		result, err := s.processOnce(ctx, key, maxAge)
		if err == nil {
			return result, nil
		}
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || (pe.Code != "40001" && pe.Code != "40P01") {
			if errors.Is(err, ErrUncertain) {
				return result, err
			}
			return result, safeError(err)
		}
		select {
		case <-ctx.Done():
			return result, ErrUnavailable
		case <-time.After(time.Duration(attempt+1) * 10 * time.Millisecond):
		}
	}
	return ProcessResult{}, ErrUnavailable
}
func (s *Store) processOnce(ctx context.Context, key []byte, maxAge time.Duration) (ProcessResult, error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	tx, err := s.begin(ctx)
	if err != nil {
		return ProcessResult{}, err
	}
	defer rollback(tx)
	result, err := processLocked(ctx, tx, key, maxAge)
	if err != nil {
		return result, err
	}
	if err = commit(ctx, tx); err != nil {
		// Retrying a stable intake identity is safe even if COMMIT's response vanished.
		if result.IntakeID != 0 {
			resolved, e := s.ResolveIntake(ctx, result.IntakeID)
			if e == nil && resolved.Processed {
				return result, nil
			}
		}
		var pe *pgconn.PgError
		if errors.As(err, &pe) && (pe.Code == "40001" || pe.Code == "40P01") {
			return result, err
		}
		return result, ErrUncertain
	}
	return result, nil
}
func processLocked(ctx context.Context, tx pgx.Tx, key []byte, maxAge time.Duration) (ProcessResult, error) {
	var session string
	err := tx.QueryRow(ctx, "SELECT session_key FROM ledger.sessions WHERE pending ORDER BY session_key FOR UPDATE SKIP LOCKED LIMIT 1").Scan(&session)
	if errors.Is(err, pgx.ErrNoRows) {
		return processInvalid(ctx, tx)
	}
	if err != nil {
		return ProcessResult{}, err
	}
	var state accounting.State
	var duration, upload, download string
	var identity []byte
	var seen *time.Time
	err = tx.QueryRow(ctx, "SELECT initialized,duration::text,upload::text,download::text,bits,marked,stopped,last_seen,identity FROM ledger.sessions WHERE session_key=$1", session).Scan(&state.Initialized, &duration, &upload, &download, &state.Bits, &state.Marked, &state.Stopped, &seen, &identity)
	if err != nil {
		return ProcessResult{}, err
	}
	state.Duration, _ = strconv.ParseUint(duration, 10, 64)
	state.Upload, _ = strconv.ParseUint(upload, 10, 64)
	state.Download, _ = strconv.ParseUint(download, 10, 64)
	if seen != nil {
		state.LastSeen = *seen
	}
	if len(identity) > 0 {
		if err = json.Unmarshal(identity, &state.Identity); err != nil {
			return ProcessResult{}, err
		}
	}
	row := tx.QueryRow(ctx, rawSelect+" WHERE session_key=$1 AND processed_at IS NULL ORDER BY CASE WHEN status_count=1 AND status IN ('Start','1') THEN 0 ELSE 1 END,id LIMIT 1", session)
	id, raw, err := scanRaw(row)
	if errors.Is(err, pgx.ErrNoRows) {
		_, err = tx.Exec(ctx, "UPDATE ledger.sessions SET pending=false WHERE session_key=$1", session)
		return ProcessResult{}, err
	}
	if err != nil {
		return ProcessResult{}, err
	}
	result := ProcessResult{IntakeID: id, Processed: true}
	event, err := accounting.Normalize(raw, key, maxAge)
	if err != nil {
		result.Reason = err.Error()
		if err = quarantineIntake(ctx, tx, id, result.Reason); err != nil {
			return result, err
		}
	} else {
		result.EventID = event.ID
		next, interval, reason := accounting.Apply(state, event)
		result.Reason = reason
		body, _ := json.Marshal(event)
		tag, err := tx.Exec(ctx, "INSERT INTO ledger.observations(event_id,intake_id,session_key,received_at,duration,upload,download,event,reason) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(event_id) DO NOTHING", event.ID, id, session, event.Received, u64(event.Duration), u64(event.Upload), u64(event.Download), body, reason)
		if err != nil {
			return result, err
		}
		if tag.RowsAffected() == 1 {
			if event.AttributionIssue != "" {
				if err = quarantineIntake(ctx, tx, id, event.AttributionIssue); err != nil {
					return result, err
				}
			}
			ident, _ := json.Marshal(next.Identity)
			_, err = tx.Exec(ctx, "UPDATE ledger.sessions SET initialized=$2,duration=$3,upload=$4,download=$5,bits=$6,marked=$7,stopped=$8,last_seen=$9,identity=$10 WHERE session_key=$1", session, next.Initialized, u64(next.Duration), u64(next.Upload), u64(next.Download), next.Bits, next.Marked, next.Stopped, next.LastSeen, ident)
			if err != nil {
				return result, err
			}
			if err = enqueue(ctx, tx, "accounting:"+event.ID, "outbox", body); err != nil {
				return result, err
			}
			if interval != nil {
				result.UsageID = interval.ID
				payload, _ := json.Marshal(interval)
				tag, err = tx.Exec(ctx, "INSERT INTO ledger.intervals(usage_id,event_id,session_key,upload,download,seconds,payload) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(usage_id) DO NOTHING", interval.ID, event.ID, session, u64(interval.Upload), u64(interval.Download), u64(interval.Seconds), payload)
				if err != nil {
					return result, err
				}
				if tag.RowsAffected() == 1 {
					if err = enqueue(ctx, tx, "usage:"+interval.ID, "outbox", payload); err != nil {
						return result, err
					}
				}
			}
		} else {
			result.Reason = "duplicate"
		}
	}
	if _, err = tx.Exec(ctx, "UPDATE ledger.intake SET processed_at=clock_timestamp(),observation_id=NULLIF($2,'') WHERE id=$1", id, result.EventID); err != nil {
		return result, err
	}
	_, err = tx.Exec(ctx, "UPDATE ledger.sessions SET pending=EXISTS(SELECT 1 FROM ledger.intake WHERE session_key=$1 AND processed_at IS NULL) WHERE session_key=$1", session)
	return result, err
}

const rawSelect = `SELECT id,received_at,source_ip,client_id,location_id,host,replay_id,
 coalesce(nas_ip,''),nas_count,coalesce(station,''),station_count,coalesce(session_id,''),session_count,
 coalesce(status,''),status_count,coalesce(session_time,''),session_time_count,
 coalesce(input_octets,''),input_octets_count,coalesce(output_octets,''),output_octets_count,
 coalesce(input_gigawords,''),input_gigawords_count,coalesce(output_gigawords,''),output_gigawords_count,
 coalesce(class,''),class_count,coalesce(called_station,''),coalesce(nas_port,'') FROM ledger.intake`

func scanRaw(row pgx.Row) (int64, accounting.Raw, error) {
	var id int64
	var r accounting.Raw
	err := row.Scan(&id, &r.Received, &r.SourceIP, &r.Client, &r.Location, &r.Host, &r.ReplayID, &r.NASIP.Value, &r.NASIP.Count, &r.Station.Value, &r.Station.Count, &r.Session.Value, &r.Session.Count, &r.Status.Value, &r.Status.Count, &r.Duration.Value, &r.Duration.Count, &r.Input.Value, &r.Input.Count, &r.Output.Value, &r.Output.Count, &r.InputHigh.Value, &r.InputHigh.Count, &r.OutputHigh.Value, &r.OutputHigh.Count, &r.Class.Value, &r.Class.Count, &r.CalledStation, &r.NASPort)
	return id, r, err
}
func quarantineIntake(ctx context.Context, tx pgx.Tx, id int64, reason string) error {
	_, err := tx.Exec(ctx, "INSERT INTO ledger.quarantine(intake_id,reason) VALUES($1,$2)", id, reason)
	return err
}
func processInvalid(ctx context.Context, tx pgx.Tx) (ProcessResult, error) {
	var id int64
	err := tx.QueryRow(ctx, "SELECT id FROM ledger.intake WHERE session_key IS NULL AND processed_at IS NULL ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1").Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ProcessResult{}, nil
	}
	if err != nil {
		return ProcessResult{}, err
	}
	if err = quarantineIntake(ctx, tx, id, "invalid_session_identity"); err != nil {
		return ProcessResult{}, err
	}
	_, err = tx.Exec(ctx, "UPDATE ledger.intake SET processed_at=clock_timestamp() WHERE id=$1", id)
	return ProcessResult{IntakeID: id, Processed: true, Reason: "invalid_session_identity"}, err
}
func u64(n uint64) string { return strconv.FormatUint(n, 10) }

// ResolveIntake answers uncertainty without inventing an identity or changing state.
func (s *Store) ResolveIntake(ctx context.Context, id int64) (ProcessResult, error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	r := ProcessResult{IntakeID: id}
	err := s.pool.QueryRow(ctx, "SELECT processed_at IS NOT NULL,coalesce(observation_id,'') FROM ledger.intake WHERE id=$1", id).Scan(&r.Processed, &r.EventID)
	return r, safeError(err)
}
func enqueue(ctx context.Context, tx pgx.Tx, id, kind string, payload []byte) error {
	tag, err := tx.Exec(ctx, "INSERT INTO ledger.work(id,kind,payload) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET id=EXCLUDED.id WHERE ledger.work.kind=EXCLUDED.kind AND ledger.work.payload=EXCLUDED.payload", id, kind, payload)
	if err == nil && tag.RowsAffected() != 1 {
		return jobs.ErrConflict
	}
	return err
}
