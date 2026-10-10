package otlp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	common "go.opentelemetry.io/proto/otlp/common/v1"

	"github.com/CampusTech/cloud-8021x/internal/jobs"
	"github.com/CampusTech/cloud-8021x/internal/telemetry"
)

func TestSynchronousHandoffClassifiesWithoutRetry(t *testing.T) {
	for _, mode := range []string{"success", "partial", "lost", "rejected"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				switch mode {
				case "success":
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{}`))
				case "partial":
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"partialSuccess":{"rejectedLogRecords":"1","errorMessage":"SECRET"}}`))
				case "lost":
					h := w.(http.Hijacker)
					c, _, _ := h.Hijack()
					_ = c.Close()
				case "rejected":
					w.WriteHeader(503)
				}
			}))
			defer server.Close()
			client, err := NewHTTP(Options{Endpoint: server.URL, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			result := client.Send(context.Background(), []telemetry.BusinessRecord{{ID: "x", Host: "origin", Category: "usage", Fields: map[string]any{"event": "Acct-Usage"}}})
			want := map[string]jobs.Outcome{"success": jobs.Succeeded, "partial": jobs.Partial, "lost": jobs.Uncertain, "rejected": jobs.Rejected}[mode]
			if result.Outcome != want || calls.Load() != 1 {
				t.Fatalf("%+v calls=%d", result, calls.Load())
			}
		})
	}
}

func TestDashboardNumericAndExactCounterRepresentations(t *testing.T) {
	r := Request([]telemetry.BusinessRecord{{Fields: map[string]any{"input_bytes": json.Number("18446744073709551615")}}})
	attrs := r.ResourceLogs[0].ScopeLogs[0].LogRecords[0].Attributes
	numeric, exact := false, false
	for _, a := range attrs {
		if a.Key == "input_bytes" {
			_, numeric = a.Value.Value.(*common.AnyValue_DoubleValue)
		}
		if a.Key == "input_bytes_exact" {
			exact = a.Value.GetStringValue() == "18446744073709551615"
		}
	}
	if !numeric || !exact {
		t.Fatal("dashboard numeric measure or exact counter missing")
	}
}

func TestStopReasonProjectsToScalarOTLPAttributeAndBody(t *testing.T) {
	r, err := telemetry.Project(jobs.Claim{ID: "accounting:stop", Payload: json.RawMessage(`{"event_id":"stop","status":"Stop","terminate_cause":"User-Request"}`)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	log := Request([]telemetry.BusinessRecord{r}).ResourceLogs[0].ScopeLogs[0].LogRecords[0]
	found := false
	for _, attr := range log.Attributes {
		if attr.Key == "terminate_cause" {
			found = attr.Value.GetStringValue() == "User-Request"
		}
	}
	var body map[string]any
	if err = json.Unmarshal([]byte(log.Body.GetStringValue()), &body); err != nil || !found || body["terminate_cause"] != "User-Request" {
		t.Fatal("missing stop-reason facet", err)
	}
}
