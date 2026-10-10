package telemetry

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestHTTPInstrumentationExcludesSecretsAndBaggage(t *testing.T) {
	cfg := config.Defaults().Telemetry
	cfg.Enabled = true
	cfg.Traces = true
	cfg.TraceSampleRatio = 1
	spans := tracetest.NewInMemoryExporter()
	s, err := newSDK(context.Background(), cfg, Identity{}, Exporters{Traces: spans}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Shutdown(context.Background()) }()
	server := httptest.NewServer(s.Handler("policy", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })))
	defer server.Close()
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/SECRET?token=SECRET", nil)
	req.Header.Set("Authorization", "Bearer SECRET")
	req.Header.Set("Baggage", "identity=SECRET")
	client := &http.Client{Transport: s.HTTPTransport("fleet", http.DefaultTransport)}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	_ = s.traces.ForceFlush(context.Background())
	got := spans.GetSpans()
	if len(got) != 2 {
		t.Fatal("missing HTTP spans", len(got))
	}
	for _, span := range got {
		for _, a := range span.Attributes {
			if strings.Contains(a.Value.String(), "SECRET") {
				t.Fatal("secret in span")
			}
		}
	}
}
