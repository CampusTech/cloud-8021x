package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/fleet"

	"github.com/CampusTech/cloud-8021x/internal/adapters/otlp"
	"github.com/CampusTech/cloud-8021x/internal/jobs"
	"github.com/CampusTech/cloud-8021x/internal/telemetry"
	collect "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/protobuf/proto"

	"github.com/CampusTech/cloud-8021x/internal/migration"
)

func TestPostgresOperatorRecoveryRetainsOriginalAndNeverResends(t *testing.T) {
	s, c := integration(t)
	reset(t, s)
	ctx := context.Background()
	_, e := s.pool.Exec(ctx, "TRUNCATE bootstrap_private.maintenance,bootstrap_private.transitions CASCADE")
	if e != nil {
		t.Fatal(e)
	}
	id, hash := strings.Repeat("8", 64), strings.Repeat("a", 64)
	gate := MaintenanceGate{Store: s}
	for _, node := range []string{"radius-primary", "radius-secondary"} {
		if e := gate.With(ctx, "fixture-fence", func(ctx context.Context) error { return s.RecordWriterFence(ctx, id, node, hash, hash) }); e != nil {
			t.Fatal(e)
		}
	}
	if e := s.BlockTransition(ctx, id); e != nil {
		t.Fatal(e)
	}
	_, e = s.pool.Exec(ctx, `INSERT INTO ledger.work(id,kind,payload,state,generation,owner) VALUES('auth:original','outbox','{"event_id":"original","event":"Access-Accept","host":"original-host","received_at":"2026-10-08T10:00:00Z"}','quarantine',7,'original-worker')`)
	if e != nil {
		t.Fatal(e)
	}
	original, e := s.LookupWork(ctx, "auth:original")
	if e != nil {
		t.Fatal(e)
	}
	digest := sha256.Sum256(original.Payload)
	request := OperatorRecoveryRequest{AcceptPossibleDuplicates: true, Transition: id, Node: "radius-primary", ConfigSHA256: hash, RequestID: strings.Repeat("b", 64), WorkID: "auth:original", Generation: 7, PayloadSHA256: hex.EncodeToString(digest[:]), Mode: "outbox-republish"}
	if e := gate.With(ctx, "work-recovery:"+request.RequestID, func(ctx context.Context) error {
		_, e := s.StartOperatorRecovery(ctx, request)
		if e == nil {
			t.Error("missing physical fences accepted")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	for _, node := range []string{"radius-primary", "radius-secondary"} {
		raw, _ := json.Marshal(migration.NodeState{Version: 1, Node: node, Inventory: migration.UnavailableInventory(), ClassKeySHA256: hash, ProviderCaches: map[string]json.RawMessage{}})
		if e := gate.With(ctx, "fixture-worker", func(ctx context.Context) error { return s.RecordWorkerState(ctx, id, hash, raw) }); e != nil {
			t.Fatal(e)
		}
	}
	runtime := runtimeStore(t, s, c)
	if _, e := runtime.OperatorRecovery(ctx, request); e == nil {
		t.Fatal("runtime read root recovery")
	}
	if _, e := s.StartOperatorRecovery(ctx, request); e == nil {
		t.Fatal("ungated recovery")
	}
	sends := 0
	if e := gate.With(ctx, "work-recovery:"+request.RequestID, func(ctx context.Context) error {
		r, e := s.StartOperatorRecovery(ctx, request)
		if e != nil {
			return e
		}
		if r.Outcome != "started" || r.Attempt < 1 {
			t.Fatal(r)
		}
		sends++
		return s.FinishOperatorRecovery(ctx, request, "uncertain", json.RawMessage(`{"outcome":"uncertain","code":"transport_failure"}`))
	}); e != nil {
		t.Fatal(e)
	}
	for range 2 {
		r, e := s.OperatorRecovery(ctx, request)
		if e != nil || r.Outcome != "uncertain" {
			t.Fatal(r, e)
		}
	}

	if e := gate.With(ctx, request.operation(), func(ctx context.Context) error {
		if _, e := s.StartOperatorRecovery(ctx, request); e == nil {
			t.Error("retained request restarted")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	native, e := New(ctx, roleDSN(t, "app_native", "disposable-native"), c)
	if e != nil {
		t.Fatal(e)
	}
	defer native.Close()
	if _, e = native.OperatorRecovery(ctx, request); e == nil {
		t.Fatal("native read private recovery")
	}
	if sends != 1 {
		t.Fatal("duplicate delivery")
	}
	after, e := s.LookupWork(ctx, request.WorkID)
	if e != nil || after.State != original.State || string(after.Payload) != string(original.Payload) || after.Generation != 7 {
		t.Fatal("original work changed", after, e)
	}
	changed := request
	changed.PayloadSHA256 = strings.Repeat("c", 64)
	if _, e := s.OperatorRecovery(ctx, changed); e == nil {
		t.Fatal("changed request reused original outcome")
	}

	for _, scenario := range []string{"success", "partial", "unknown", "started-crash", "receipt-lost-ack", "before-sql"} {
		t.Run(scenario, func(t *testing.T) {
			req := request
			sum := sha256.Sum256([]byte(scenario))
			req.RequestID = hex.EncodeToString(sum[:])
			posts := 0
			receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				posts++
				body, _ := io.ReadAll(r.Body)
				var got collect.ExportLogsServiceRequest
				if e := proto.Unmarshal(body, &got); e != nil || len(got.ResourceLogs) != 1 || len(got.ResourceLogs[0].ScopeLogs[0].LogRecords) != 1 {
					t.Error("invalid single original payload", e)
				}
				w.Header().Set("Content-Type", "application/json")
				switch scenario {
				case "partial":
					_, _ = w.Write([]byte(`{"partialSuccess":{"rejectedLogRecords":"1"}}`))
				case "unknown":
					_, _ = w.Write([]byte(`not-json`))
				default:
					_, _ = w.Write([]byte(`{}`))
				}
			}))
			defer receiver.Close()
			transport, e := otlp.NewHTTP(otlp.Options{Endpoint: receiver.URL, Timeout: time.Second})
			if e != nil {
				t.Fatal(e)
			}
			var attempt int64
			e = gate.With(ctx, req.operation(), func(ctx context.Context) error {
				if scenario == "before-sql" {
					attempt, e = s.OperatorMaintenanceAttempt(ctx, req)
					if e != nil {
						return e
					}
					return errors.New("injected stop before SQL")
				}
				started, e := s.StartOperatorRecovery(ctx, req)
				if e != nil {
					return e
				}
				attempt = started.Attempt
				if scenario == "started-crash" {
					return errors.New("injected crash before send")
				}
				record, e := telemetry.Project(jobs.Claim{ID: req.WorkID, Kind: "outbox", Payload: started.Original.Payload}, nil)
				if e != nil {
					return e
				}
				if record.ID != "original" || record.Host != "original-host" || record.Received.Format(time.RFC3339) != "2026-10-08T10:00:00Z" {
					t.Fatal("republication altered original identity/time")
				}
				receipt := transport.Send(ctx, []telemetry.BusinessRecord{record})
				raw, _ := json.Marshal(receipt)
				if e = s.FinishOperatorRecovery(ctx, req, string(receipt.Outcome), raw); e != nil {
					return e
				}
				if scenario == "receipt-lost-ack" {
					return errors.New("injected lost completion acknowledgement")
				}
				return nil
			})
			if scenario == "started-crash" || scenario == "receipt-lost-ack" || scenario == "before-sql" {
				if e == nil {
					t.Fatal("injected crash disappeared")
				}
				if _, e = s.pool.Exec(ctx, `UPDATE bootstrap_private.maintenance SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, attempt); e != nil {
					t.Fatal(e)
				}
				if e = s.RecoverOperatorAttempt(ctx, req, attempt, func() ([]byte, error) { return nil, errors.New("helper live") }); e == nil {
					t.Fatal("live helper accepted")
				}

				wrong := req
				wrong.ConfigSHA256 = strings.Repeat("f", 64)
				if e = s.RecoverOperatorAttempt(ctx, wrong, attempt, func() ([]byte, error) { return OperatorWorkArchive(original), nil }); e == nil {
					t.Fatal("changed config recovery accepted")
				}
				stopped, cancel := context.WithCancel(ctx)
				cancel()
				if e = s.RecoverOperatorAttempt(stopped, req, attempt, func() ([]byte, error) {
					t.Error("failed query reached absence proof")
					return OperatorWorkArchive(original), nil
				}); e == nil {
					t.Fatal("query failure proved absence")
				}
				if scenario == "before-sql" {
					if _, e = s.pool.Exec(ctx, `UPDATE ledger.work SET owner='changed' WHERE id=$1`, req.WorkID); e != nil {
						t.Fatal(e)
					}
					if e = s.RecoverOperatorAttempt(ctx, req, attempt, func() ([]byte, error) { return OperatorWorkArchive(original), nil }); e == nil {
						t.Fatal("changed original work accepted")
					}
					if _, e = s.pool.Exec(ctx, `UPDATE ledger.work SET owner=$2 WHERE id=$1`, req.WorkID, original.Owner); e != nil {
						t.Fatal(e)
					}
				}
				if e = s.RecoverOperatorAttempt(ctx, req, attempt, func() ([]byte, error) { return OperatorWorkArchive(original), nil }); e != nil {
					t.Fatal(e)
				}
			} else if e != nil {
				t.Fatal(e)
			}
			want := "succeeded"
			switch scenario {
			case "partial":
				want = "partial"
			case "before-sql":
				want = "no_send_proven"
			case "unknown", "started-crash":
				want = "uncertain"
			}
			for range 2 {
				got, e := s.OperatorRecovery(ctx, req)
				if e != nil || got.Outcome != want {
					t.Fatal(got, e)
				}
			}
			expectedPosts := 1
			if scenario == "started-crash" || scenario == "before-sql" {
				expectedPosts = 0
			}
			if posts != expectedPosts {
				t.Fatal("unexpected resend", posts)
			}
			if e = s.OriginalOutboxSucceeded(ctx, req.WorkID, req.Generation, req.PayloadSHA256); e == nil {
				t.Fatal("successor receipt changed original delivery outcome")
			}
		})
	}

	t.Run("fleet-terminal-preserves-original", func(t *testing.T) {
		payload := json.RawMessage(`{"host_id":42,"host_uuid":"original-host","command_uuid":"original-command","collection_key":"original-key"}`)
		if _, e := s.pool.Exec(ctx, `INSERT INTO ledger.work(id,kind,payload,state,generation,receipt) VALUES('fleet-cert:original','fleet-cert:scope',$1,'started',3,'{"pending":true}')`, []byte(payload)); e != nil {
			t.Fatal(e)
		}
		original, e := s.LookupWork(ctx, "fleet-cert:original")
		if e != nil {
			t.Fatal(e)
		}
		digest := sha256.Sum256(original.Payload)
		req := request
		req.RequestID = strings.Repeat("c", 64)
		req.WorkID = "fleet-cert:original"
		req.Generation = 3
		req.Mode = "fleet-terminal"
		req.AcceptPossibleDuplicates = false
		req.PayloadSHA256 = hex.EncodeToString(digest[:])
		proof := fleet.LegacyRecoveryEvidence{CommandUUID: "original-command", HostUUID: "original-host", HostID: 42, Outcome: "terminal", Response: json.RawMessage(`{"status":"Error","updated_at":"2026-10-08T10:00:00Z"}`)}
		if e := gate.With(ctx, req.operation(), func(ctx context.Context) error {
			if _, e := s.StartOperatorRecovery(ctx, req); e != nil {
				return e
			}
			wrong := proof
			wrong.HostUUID = "wrong"
			if e := s.FinishFleetRecovery(ctx, req, wrong); e == nil {
				t.Error("different terminal target accepted")
			}
			return s.FinishFleetRecovery(ctx, req, proof)
		}); e != nil {
			t.Fatal(e)
		}
		out, e := s.OperatorRecovery(ctx, req)
		if e != nil || out.Outcome != "terminal" || string(out.Original.Payload) != string(original.Payload) || string(out.Original.Receipt) != string(original.Receipt) {
			t.Fatal("original Fleet evidence lost", out, e)
		}
		now, e := s.LookupWork(ctx, req.WorkID)
		if e != nil || now.State != "succeeded" || string(now.Payload) != string(original.Payload) || bytes.Contains(now.Receipt, []byte("observation")) {
			t.Fatal("terminal recovery changed certificate authority", now, e)
		}
	})
	if e := s.WorkersAllowed(ctx, id); e == nil {
		t.Fatal("recovery enabled workers", e)
	}
}
