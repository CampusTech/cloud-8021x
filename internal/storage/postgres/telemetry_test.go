package postgres

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/otlp"
	"github.com/CampusTech/cloud-8021x/internal/events/auth"
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
