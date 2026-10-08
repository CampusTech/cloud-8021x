package telemetry

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/sirupsen/logrus"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

type captureLogs struct {
	mu      sync.Mutex
	records []sdklog.Record
}

func (c *captureLogs) Export(_ context.Context, r []sdklog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, x := range r {
		c.records = append(c.records, x.Clone())
	}
	return nil
}
func (c *captureLogs) ForceFlush(context.Context) error { return nil }
func (c *captureLogs) Shutdown(context.Context) error   { return nil }
func TestSDKCorrelationResourceAndRedaction(t *testing.T) {
	cfg := config.Defaults().Telemetry
	cfg.Enabled = true
	cfg.Logs = true
	cfg.Traces = true
	cfg.TraceSampleRatio = 1
	logs := &captureLogs{}
	spans := tracetest.NewInMemoryExporter()
	var local bytes.Buffer
	s, err := newSDK(context.Background(), cfg, Identity{Version: "test", Instance: "node-b", Environment: "test", Host: "radius-b"}, Exporters{Logs: logs, Traces: spans}, &local)
	if err != nil {
		t.Fatal(err)
	}
	ctx, span := s.Tracer.Start(context.Background(), "policy")
	s.Logger.WithContext(ctx).WithFields(logrus.Fields{"operation": "policy", "outcome": "success", "password": "SENTINEL", "url": "https://secret:SENTINEL@host/?token=SENTINEL", "error": context.Canceled}).Info("policy")
	span.End()
	defer func() { _ = s.Shutdown(context.Background()) }()
	if err = s.logs.ForceFlush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(local.String(), "SENTINEL") {
		t.Fatal("local secret leakage")
	}
	_ = s.traces.ForceFlush(context.Background())
	if len(logs.records) != 1 || len(spans.GetSpans()) != 1 {
		t.Fatalf("missing signals logs=%d spans=%d", len(logs.records), len(spans.GetSpans()))
	}
	r := logs.records[0]
	if !r.TraceID().IsValid() || r.TraceID() != spans.GetSpans()[0].SpanContext.TraceID() {
		t.Fatal("missing correlation")
	}
	values := map[string]string{}
	for _, a := range r.Resource().Attributes() {
		values[string(a.Key)] = a.Value.AsString()
	}
	if values["service.name"] != "cloud-8021x" || values["host.name"] != "radius-b" || values["service.instance.id"] != "node-b" {
		t.Fatalf("resource: %v", values)
	}
}

type failingLogs struct{}

func (failingLogs) Export(ctx context.Context, _ []sdklog.Record) error {
	<-ctx.Done()
	return ctx.Err()
}
func (failingLogs) ForceFlush(ctx context.Context) error { return ctx.Err() }
func (failingLogs) Shutdown(context.Context) error       { return nil }
func TestBoundedTelemetryFailureAndSampling(t *testing.T) {
	cfg := config.Defaults().Telemetry
	cfg.Enabled = true
	cfg.Logs = true
	cfg.Traces = true
	cfg.QueueSize = 4
	cfg.Timeout = 10 * time.Millisecond
	cfg.ShutdownTimeout = 30 * time.Millisecond
	cfg.TraceSampleRatio = 0
	spans := tracetest.NewInMemoryExporter()
	var local bytes.Buffer
	s, err := newSDK(context.Background(), cfg, Identity{Host: "node"}, Exporters{Logs: failingLogs{}, Traces: spans}, &local)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for range 1000 {
		s.Logger.Info("policy")
	}
	if time.Since(start) > time.Second {
		t.Fatal("logging blocks caller")
	}
	_, span := s.Tracer.Start(context.Background(), "policy")
	span.End()
	_ = s.Shutdown(context.Background())
	if time.Since(start) > time.Second {
		t.Fatal("shutdown unbounded")
	}
	if len(spans.GetSpans()) != 0 {
		t.Fatal("sample ratio ignored")
	}
}

func TestInitializeCannotInstallCompetingProviders(t *testing.T) {
	cfg := config.Defaults().Telemetry
	s, err := Initialize(context.Background(), cfg, Identity{Host: "once"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Shutdown(context.Background()) }()
	if _, err = Initialize(context.Background(), cfg, Identity{Host: "twice"}, io.Discard); err == nil {
		t.Fatal("second global initialization accepted")
	}
}
func TestOrdinarySignalsReachFakeOTLPAsynchronously(t *testing.T) {
	var mu sync.Mutex
	paths := map[string]int{}
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		if bytes.Contains(data, []byte("SENTINEL")) {
			t.Error("secret reached OTLP")
		}
		mu.Lock()
		paths[r.URL.Path]++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(200)
	}))
	defer receiver.Close()
	cfg := config.Defaults().Telemetry
	cfg.Enabled = true
	cfg.Logs = true
	cfg.Traces = true
	cfg.Metrics = true
	cfg.Endpoint = receiver.URL
	cfg.TraceSampleRatio = 1
	ex, err := exporters(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	s, err := newSDK(context.Background(), cfg, Identity{Host: "producer"}, ex, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Shutdown(context.Background()) }()
	ctx, span := s.Tracer.Start(context.Background(), "policy")
	s.Logger.WithContext(ctx).WithField("secret", "SENTINEL").Info("policy")
	span.End()
	s.Metrics.Observe(ctx, "outbox.depth", 1)
	if err = errors.Join(s.logs.ForceFlush(ctx), s.traces.ForceFlush(ctx), s.metrics.ForceFlush(ctx)); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, path := range []string{"/v1/logs", "/v1/traces", "/v1/metrics"} {
		if paths[path] != 1 {
			t.Fatalf("missing or duplicate remote signal %s: %v", path, paths)
		}
	}
}
