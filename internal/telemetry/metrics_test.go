package telemetry

import (
	"context"
	"sync/atomic"
	"testing"

	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestNeutralMetricsBoundLabelsAndUnknownObservations(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	defer func() { _ = provider.Shutdown(context.Background()) }()
	m := newMeasurements(provider.Meter("test"), &atomic.Uint64{})
	m.Observe(context.Background(), "outbox.depth", 3)
	m.Observe(context.Background(), "device.SECRET", 10)
	m.Retry(context.Background(), "owner@example.com")
	var result metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &result); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, scope := range result.ScopeMetrics {
		for _, data := range scope.Metrics {
			if data.Name == "cloud8021x.outbox.depth" {
				found = true
				if data.Data.(metricdata.Gauge[float64]).DataPoints[0].Value != 3 {
					t.Fatal("bad depth")
				}
			}
			if data.Name == "cloud8021x.api.retries" {
				for _, point := range data.Data.(metricdata.Sum[int64]).DataPoints {
					for _, attr := range point.Attributes.ToSlice() {
						if attr.Value.AsString() != "other" {
							t.Fatal("unbounded metric label")
						}
					}
				}
			}
			if data.Name == "cloud8021x.native.write_failures" {
				t.Fatal("invented native observation")
			}
		}
	}
	if !found {
		t.Fatal("no neutral metric")
	}
}
