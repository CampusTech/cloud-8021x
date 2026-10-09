package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting"
	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/migration"
	"github.com/jackc/pgx/v5"
)

// ImportLegacyUsage validates every field before opening the import transaction.
// It intentionally creates no native cursor and no sendable legacy outbox work.
// The full state orchestrator records state:<transition> only after all domains
// commit; this narrower usage marker cannot enable background workers by itself.
func (s *Store) ImportLegacyUsage(ctx context.Context, id string, data []byte, hosts []string) (bool, error) {
	checkpoint, err := migration.DecodeUsage(data, hosts)
	if err != nil {
		return false, err
	}
	if err = s.RequireWriterFences(ctx, id); err != nil {
		return false, err
	}
	sum := sha256.Sum256(data)
	checksum := hex.EncodeToString(sum[:])
	return s.ImportOnce(ctx, "usage:"+id, checksum, func(ctx context.Context, tx pgx.Tx) error {
		var enabled, blocked bool
		if err := tx.QueryRow(ctx, `SELECT enabled,blocked FROM bootstrap_private.transitions WHERE id=$1 FOR UPDATE`, id).Scan(&enabled, &blocked); err != nil {
			return err
		}
		if enabled || blocked {
			return errors.New("usage import requires stopped transition")
		}
		return importLegacyUsageTx(ctx, tx, id, data, hosts, checkpoint)
	})
}

func (s *Store) RecordWorkerFence(ctx context.Context, id, node, receipt string) error {
	scope, ok := ctx.Value(maintenanceScopeKey{}).(*maintenanceScope)
	if !ok || scope.store != s || !scope.active.Load() || !transitionDigest.MatchString(id) || !transitionDigest.MatchString(receipt) || (node != "radius-primary" && node != "radius-secondary") {
		return errors.New("protected worker quiescence evidence required")
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	tag, err := s.pool.Exec(ctx, `INSERT INTO bootstrap_private.worker_fences(transition,node,receipt_sha256) SELECT $1,$2,$3 WHERE EXISTS(SELECT 1 FROM bootstrap_private.transitions WHERE id=$1 AND blocked AND NOT enabled) ON CONFLICT(transition,node) DO UPDATE SET receipt_sha256=EXCLUDED.receipt_sha256 WHERE worker_fences.receipt_sha256=EXCLUDED.receipt_sha256`, id, node, receipt)
	if err != nil {
		return safeError(err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("revoke transition before fencing workers; receipt must match")
	}
	return nil
}
func (s *Store) ExportLegacyUsage(ctx context.Context, id string) ([]byte, error) {
	if !transitionDigest.MatchString(id) {
		return nil, errors.New("invalid transition")
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, safeError(err)
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(8021,2)"); err != nil {
		return nil, safeError(err)
	}
	var fenced bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bootstrap_private.transitions t WHERE t.id=$1 AND t.blocked AND NOT t.enabled AND (SELECT count(*) FROM bootstrap_private.worker_fences f WHERE f.transition=t.id)=2)`, id).Scan(&fenced); err != nil {
		return nil, safeError(err)
	}
	if !fenced {
		return nil, errors.New("both Go worker fences required before rollback export")
	}
	var original []byte
	var hosts []string
	if err = tx.QueryRow(ctx, `SELECT document,hosts FROM bootstrap_private.legacy_usage WHERE transition=$1`, id).Scan(&original, &hosts); err != nil {
		return nil, safeError(err)
	}
	checkpoint, err := migration.DecodeUsage(original, hosts)
	if err != nil {
		return nil, err
	}
	// A native receipt cannot prove completion of missing historical DD windows.
	// Keep the original incomplete checkpoint byte-exact; current sessions and
	// outcomes are retained separately in the full cold rollback archive.
	if checkpoint.Version == 2 {
		return original, nil
	}
	prior := map[string]migration.LegacySession{}
	for _, session := range checkpoint.Tracker.Sessions {
		prior[accounting.SessionKey(session.Key)] = session
	}
	checkpoint.Tracker.Sessions = []migration.LegacySession{}
	rows, err := tx.Query(ctx, `SELECT session_key,duration::text,upload::text,download::text,bits,marked,stopped,last_seen,identity FROM ledger.sessions WHERE initialized ORDER BY session_key`)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	for rows.Next() {
		var key, duration, upload, download string
		var bits int
		var marked, stopped bool
		var seen time.Time
		var raw []byte
		if err = rows.Scan(&key, &duration, &upload, &download, &bits, &marked, &stopped, &seen, &raw); err != nil {
			return nil, safeError(err)
		}
		session, exists := prior[key]
		if !exists {
			session.Key, err = decodeSessionKey(key)
			if err != nil {
				return nil, err
			}
			session.Display = map[string]json.RawMessage{}
		}
		session.Duration, err = strconv.ParseUint(duration, 10, 64)
		if err != nil {
			return nil, err
		}
		session.Upload, err = strconv.ParseUint(upload, 10, 64)
		if err != nil {
			return nil, err
		}
		session.Download, err = strconv.ParseUint(download, 10, 64)
		if err != nil {
			return nil, err
		}
		session.CounterBits = bits
		session.FormatMarked = marked
		session.Stopped = stopped
		oldTime, e := migration.ReceiptTime([]byte(session.LastSeen))
		if e != nil || oldTime.UnixMicro() != seen.UnixMicro() {
			session.LastSeen = json.Number(fmt.Sprintf("%d.%06d", seen.Unix(), seen.Nanosecond()/1000))
		}
		var identity *binding.Attribution
		if json.Unmarshal(raw, &identity) != nil {
			return nil, errors.New("invalid ledger identity")
		}
		if identity != nil {
			if session.Identity == nil || session.Identity.DeviceID != string(identity.DeviceID) || session.Identity.Fingerprint != identity.Fingerprint {
				session.Identity = &migration.LegacyIdentity{Verified: true, DeviceID: string(identity.DeviceID), Fingerprint: identity.Fingerprint}
			}
			if identity.VLAN != nil {
				session.Display["vlan_id"], _ = json.Marshal(*identity.VLAN)
			}
		}
		checkpoint.Tracker.Sessions = append(checkpoint.Tracker.Sessions, session)
	}
	if err = rows.Err(); err != nil {
		return nil, safeError(err)
	}
	// Original DD through/credit boundary and pending/uncertain bytes remain.
	// New already-exported business events are not converted into resend batches.
	return checkpoint.Encode()
}
func decodeSessionKey(input string) ([4]string, error) {
	var parts [4]string
	for i := range parts {
		pos := strings.IndexByte(input, ':')
		if pos <= 0 {
			return parts, errors.New("invalid ledger session key")
		}
		size, e := strconv.Atoi(input[:pos])
		input = input[pos+1:]
		if e != nil || size < 1 || size > len(input) {
			return parts, errors.New("invalid ledger session key")
		}
		parts[i] = input[:size]
		input = input[size:]
	}
	if input != "" {
		return parts, errors.New("invalid ledger session key")
	}
	return parts, nil
}

func importLegacyUsageTx(ctx context.Context, tx pgx.Tx, id string, data []byte, hosts []string, checkpoint migration.UsageCheckpoint) error {
	if checkpoint.Version == 2 {
		if _, err := tx.Exec(ctx, `INSERT INTO ledger.legacy_usage_floor(singleton,transition,credit_start) VALUES(true,$1,$2)`, id, string(checkpoint.CreditStart)); err != nil {
			return err
		}
	}
	for _, session := range checkpoint.Tracker.Sessions {
		seen, err := migration.ReceiptTime([]byte(session.LastSeen))
		if err != nil {
			return err
		}
		var identity *binding.Attribution
		if session.Identity != nil {
			fp, e := domain.NormalizeFingerprint(session.Identity.Fingerprint)
			if e == nil {
				identity = &binding.Attribution{DeviceID: domain.DeviceID(session.Identity.DeviceID), Fingerprint: fp}
				var vlan int
				var text string
				if raw := session.Display["vlan_id"]; json.Unmarshal(raw, &text) == nil {
					vlan, _ = strconv.Atoi(text)
				} else {
					_ = json.Unmarshal(raw, &vlan)
				}
				if domain.ValidVLAN(vlan) {
					identity.VLAN = &vlan
				}
			}
		}
		raw, err := json.Marshal(identity)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO ledger.sessions(session_key,pending,initialized,duration,upload,download,bits,marked,stopped,last_seen,identity) VALUES($1,false,true,$2,$3,$4,$5,$6,$7,$8,$9)`, accounting.SessionKey(session.Key), u64(session.Duration), u64(session.Upload), u64(session.Download), session.CounterBits, session.FormatMarked, session.Stopped, seen, raw); err != nil {
			return err
		}
	}
	for _, pending := range checkpoint.Pending {
		var p struct {
			ID string `json:"usage_id"`
		}
		if json.Unmarshal(pending, &p) != nil {
			return errors.New("invalid pending usage")
		}
		workID := "legacy-usage:" + p.ID
		if _, err := tx.Exec(ctx, `INSERT INTO ledger.work(id,kind,payload,state,receipt) VALUES($1,'legacy-usage',$2,'quarantine','{"reason":"legacy_delivery_requires_reconciliation"}')`, workID, []byte(pending)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ledger.quarantine(work_id,reason,payload) VALUES($1,'legacy_delivery_requires_reconciliation',$2)`, workID, []byte(pending)); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `INSERT INTO bootstrap_private.legacy_usage(transition,document,hosts) VALUES($1,$2,$3)`, id, data, hosts)
	return err
}
