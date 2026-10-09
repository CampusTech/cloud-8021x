package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/otlp"
	"github.com/CampusTech/cloud-8021x/internal/events/auth"
	"github.com/CampusTech/cloud-8021x/internal/jobs"
	"github.com/CampusTech/cloud-8021x/internal/telemetry"
)

func TestPostgresTelemetryHandoff(t *testing.T) {
	for _, mode := range []string{"success", "partial", "lost", "reject"} {
		t.Run(mode, func(t *testing.T) {
			admin, c := integration(t)
			reset(t, admin)
			s := runtimeStore(t, admin, c)
			ctx := context.Background()
			payload, _ := json.Marshal(auth.Event{ID: "one", Event: "Access-Accept", Host: "producer-a", Received: time.Now()})
			if err := s.Reserve(ctx, "auth:one", "outbox", payload); err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				state, err := s.LookupWork(ctx, "auth:one")
				if err != nil || state.State != "started" {
					t.Error("external I/O before durable started", state, err)
				}
				switch mode {
				case "success":
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{}`))
				case "partial":
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"partialSuccess":{"rejectedLogRecords":"1"}}`))
				case "lost":
					h := w.(http.Hijacker)
					conn, _, _ := h.Hijack()
					_ = conn.Close()
				case "reject":
					w.WriteHeader(503)
				}
			}))
			defer receiver.Close()
			transport, err := otlp.NewHTTP(otlp.Options{Endpoint: receiver.URL, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			outbox := telemetry.Outbox{Store: s, Transport: transport, Owner: "worker-b", Timeout: time.Second}
			if worked, err := outbox.One(ctx); !worked || err != nil {
				t.Fatal(worked, err)
			}
			if worked, err := outbox.One(ctx); worked || err != nil {
				t.Fatal("retried finalized handoff", worked, err)
			}
			state, err := s.LookupWork(ctx, "auth:one")
			if err != nil {
				t.Fatal(err)
			}
			want := "quarantine"
			if mode == "success" {
				want = "succeeded"
			}
			if state.State != want || len(state.Payload) == 0 || len(state.Receipt) == 0 || calls.Load() != 1 {
				t.Fatalf("state=%+v calls=%d", state, calls.Load())
			}
			var attempts int
			if err = admin.pool.QueryRow(ctx, "SELECT count(*) FROM ledger.attempts WHERE work_id='auth:one'").Scan(&attempts); err != nil || attempts != 1 {
				t.Fatal(attempts, err)
			}
			health, err := s.ObserveDelivery(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if mode != "success" && health.Quarantined != 1 {
				t.Fatal("missing delivery health", health)
			}
		})
	}
}
func TestPostgresTelemetryEmptyFreshnessUnknown(t *testing.T) {
	admin, c := integration(t)
	reset(t, admin)
	s := runtimeStore(t, admin, c)
	health, err := s.ObserveDelivery(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if health.UsageAge != nil || health.OutboxOldestAge != nil {
		t.Fatalf("empty ledger fabricated freshness: %+v", health)
	}
}

func TestPostgresTelemetryTerminationMigrationAndImmutableDedup(t *testing.T) {
	admin, c := integration(t)
	reset(t, admin)
	ctx := context.Background()
	// Recreate the exact v2 column contract in this disposable fixture, leaving a
	// pending old raw row and an immutable already-reserved payload across upgrade.
	if _, err := admin.pool.Exec(ctx, "ALTER TABLE ledger.intake DROP COLUMN terminate_cause, DROP COLUMN terminate_cause_count; ALTER TABLE ledger.sessions DROP COLUMN native_baseline_required; DROP TABLE ledger.legacy_usage_floor; DELETE FROM ledger.schema_version WHERE version>=3"); err != nil {
		t.Fatal(err)
	}
	legacy := testRaw("old-stop", "Stop")
	if err := insertRaw(ctx, admin, legacy); err != nil {
		t.Fatal(err)
	}
	s := runtimeStore(t, admin, c)
	old := json.RawMessage(`{"event_id":"legacy","status":"Stop"}`)
	if err := s.Reserve(ctx, "accounting:legacy", "outbox", old); err != nil {
		t.Fatal(err)
	}
	before, _ := s.LookupWork(ctx, "accounting:legacy")
	if err := admin.Migrate(ctx, Roles{Runtime: "app_runtime", Native: "app_native"}); err != nil {
		t.Fatal(err)
	}
	if err := admin.Migrate(ctx, Roles{Runtime: "app_runtime", Native: "app_native"}); err != nil {
		t.Fatal("idempotent migration", err)
	}
	var absent bool
	if err := admin.pool.QueryRow(ctx, "SELECT terminate_cause IS NULL AND terminate_cause_count=0 FROM ledger.intake").Scan(&absent); err != nil || !absent {
		t.Fatal(absent, err)
	}
	if err := drain(ctx, s); err != nil {
		t.Fatal(err)
	}
	var legacyID string
	if err := admin.pool.QueryRow(ctx, "SELECT observation_id FROM ledger.intake").Scan(&legacyID); err != nil {
		t.Fatal(err)
	}
	immutable, _ := s.LookupWork(ctx, "accounting:"+legacyID)
	// Better display metadata on a retransmission must not rewrite or republish.
	if err := insertRaw(ctx, admin, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.pool.Exec(ctx, "UPDATE ledger.intake SET terminate_cause='User-Request',terminate_cause_count=1 WHERE processed_at IS NULL"); err != nil {
		t.Fatal(err)
	}
	if err := drain(ctx, s); err != nil {
		t.Fatal(err)
	}
	after, _ := s.LookupWork(ctx, "accounting:"+legacyID)
	if string(immutable.Payload) != string(after.Payload) || count(t, admin, "observations") != 1 {
		t.Fatal("duplicate rewrote immutable event")
	}
	cases := []struct {
		value string
		count int
		want  string
	}{{"Lost-Carrier", 1, "Lost-Carrier"}, {"User-Request", 2, "N/A"}, {"9999", 1, "N/A"}}
	for i, tc := range cases {
		r := testRaw(fmt.Sprintf("cause-%d", i), "Stop")
		if err := insertRaw(ctx, admin, r); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.pool.Exec(ctx, "UPDATE ledger.intake SET terminate_cause=$1,terminate_cause_count=$2 WHERE processed_at IS NULL", tc.value, tc.count); err != nil {
			t.Fatal(err)
		}
		if err := drain(ctx, s); err != nil {
			t.Fatal(err)
		}
		var id string
		if err := admin.pool.QueryRow(ctx, "SELECT observation_id FROM ledger.intake WHERE session_id=$1", r.Session.Value).Scan(&id); err != nil {
			t.Fatal(err)
		}
		work, err := s.LookupWork(ctx, "accounting:"+id)
		if err != nil {
			t.Fatal(err)
		}
		projected, err := telemetry.Project(jobs.Claim{ID: "accounting:" + id, Payload: work.Payload}, nil)
		if err != nil || projected.Fields["terminate_cause"] != tc.want {
			t.Fatal(projected, err)
		}
	}
	unchanged, _ := s.LookupWork(ctx, "accounting:legacy")
	if string(before.Payload) != string(unchanged.Payload) {
		t.Fatal("migration rewrote legacy payload")
	}
	projected, err := telemetry.Project(jobs.Claim{ID: "accounting:legacy", Payload: unchanged.Payload}, nil)
	if err != nil || projected.Fields["terminate_cause"] != "N/A" {
		t.Fatal(projected, err)
	}
}

func TestPostgresOnlineSessionsExcludeStaleTerminalAndUnknown(t *testing.T) {
	admin, c := integration(t)
	reset(t, admin)
	ctx := context.Background()
	_, err := admin.pool.Exec(ctx, `INSERT INTO ledger.sessions(session_key,initialized,stopped,last_seen) VALUES ('fresh',true,false,clock_timestamp()-interval '1 minute'),('stale',true,false,clock_timestamp()-interval '16 minutes'),('stopped',true,true,clock_timestamp()),('unknown',true,false,NULL),('future',true,false,clock_timestamp()+interval '1 hour')`)
	if err != nil {
		t.Fatal(err)
	}
	h, err := runtimeStore(t, admin, c).ObserveDelivery(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if h.Sessions != 1 {
		t.Fatalf("online count=%d want 1", h.Sessions)
	}
}
