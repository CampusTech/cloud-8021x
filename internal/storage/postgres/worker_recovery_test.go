package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/migration"
)

func TestPostgresWorkerFenceResumeAtStopCaptureAndAcknowledgement(t *testing.T) {
	s, c := integration(t)
	ctx := context.Background()
	for _, boundary := range []string{"stop", "capture", "ack"} {
		t.Run(boundary, func(t *testing.T) {
			if _, e := s.pool.Exec(ctx, "TRUNCATE bootstrap_private.maintenance,bootstrap_private.transitions CASCADE"); e != nil {
				t.Fatal(e)
			}
			id, hash := strings.Repeat("8", 64), strings.Repeat("a", 64)
			identity := WorkerFenceIdentity{WriterFenceIdentity: WriterFenceIdentity{Transition: id, Node: "radius-primary", ConfigSHA256: hash}}
			gate := MaintenanceGate{Store: s}
			if e := gate.With(ctx, "fixture-original-fence", func(ctx context.Context) error { return s.RecordWriterFence(ctx, id, identity.Node, hash, hash) }); e != nil {
				t.Fatal(e)
			}
			state := migration.NodeState{Version: 1, Node: identity.Node, Inventory: json.RawMessage(`{"version":2,"updated_at":1791453700.999999999,"identities":{},"certificates":{},"hardware_serials":{}}`), ClassKeySHA256: hash, ProviderCaches: map[string]json.RawMessage{}}
			raw, _ := json.Marshal(state)
			operation, _ := identity.Operation()
			var attempt int64
			if e := gate.With(ctx, operation, func(ctx context.Context) error {
				var e error
				attempt, e = s.WorkerFenceAttempt(ctx, identity)
				if e != nil {
					return e
				}
				if e = s.BlockTransition(ctx, id); e != nil {
					return e
				}
				if boundary == "ack" {
					if e = s.RecordWorkerState(ctx, id, hash, raw); e != nil {
						return e
					}
				}
				return errors.New("interrupted " + boundary)
			}); e == nil {
				t.Fatal("interruption not retained")
			}
			calls := 0
			resume := func(context.Context) (string, []byte, error) { calls++; return hash, raw, nil }
			if e := s.ResumeWorkerFence(ctx, attempt, identity, resume); e == nil || calls != 0 {
				t.Fatal("live worker helper resumed")
			}
			if _, e := s.pool.Exec(ctx, `UPDATE bootstrap_private.maintenance SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, attempt); e != nil {
				t.Fatal(e)
			}
			wrong := identity
			wrong.ConfigSHA256 = strings.Repeat("b", 64)
			if e := s.ResumeWorkerFence(ctx, attempt, wrong, resume); e == nil || calls != 0 {
				t.Fatal("wrong config recovery")
			}
			if e := runtimeStore(t, s, c).ResumeWorkerFence(ctx, attempt, identity, resume); e == nil || calls != 0 {
				t.Fatal("runtime entered root recovery")
			}
			if e := s.ResumeWorkerFence(ctx, attempt, identity, resume); e != nil || calls != 1 {
				t.Fatal("exact bounded worker recovery failed", e)
			}
			var captured []byte
			if e := s.pool.QueryRow(ctx, `SELECT document FROM bootstrap_private.worker_states WHERE transition=$1 AND node=$2`, id, identity.Node).Scan(&captured); e != nil || string(captured) != string(raw) {
				t.Fatal("captured state changed", e)
			}
			var n int
			if e := s.pool.QueryRow(ctx, `SELECT count(*) FROM bootstrap_private.maintenance_recoveries WHERE attempt=$1`, attempt).Scan(&n); e != nil || n != 1 {
				t.Fatal("recovery observation missing", e)
			}
			if e := s.WorkersAllowed(ctx, id); e == nil {
				t.Fatal("recovery enabled workers")
			}
		})
	}
}
