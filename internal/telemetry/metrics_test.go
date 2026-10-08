package telemetry

import (
	"context"
	"math"
	"strings"
	"sync/atomic"
	"testing"

	"go.opentelemetry.io/otel/attribute"

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

func TestComponentMeasurementsAreDistinctAndBounded(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	defer func() { _ = provider.Shutdown(context.Background()) }()
	m := newMeasurements(provider.Meter("test"), &atomic.Uint64{})
	ctx := context.Background()
	for _, name := range []string{"backend.up", "backend.uptime", "job.age"} {
		labels := []string{"freeradius", "step-ca"}
		if name == "job.age" {
			labels = []string{"inventory", "outbox"}
		}
		m.ObserveComponent(ctx, name, labels[0], 1)
		m.ObserveComponent(ctx, name, labels[1], 2)
		m.ObserveComponent(ctx, name, "owner@example.com", 3)
		m.ObserveComponent(ctx, name, labels[0], math.NaN())
		m.ObserveComponent(ctx, name, labels[0], math.Inf(1))
		m.ObserveComponent(ctx, name, "postgres", -1)
		m.ObserveComponent(ctx, name, labels[0], -1) // unavailable is omitted
		m.Observe(ctx, name, 9)                      // component gauges cannot create unlabeled series
	}
	var result metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &result); err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, scope := range result.ScopeMetrics {
		for _, data := range scope.Metrics {
			if data.Name != "cloud8021x.backend.up" && data.Name != "cloud8021x.backend.uptime" && data.Name != "cloud8021x.job.age" {
				continue
			}
			found++
			points := data.Data.(metricdata.Gauge[float64]).DataPoints
			if len(points) != 2 {
				t.Fatalf("%s series: %+v", data.Name, points)
			}
			want := map[string]float64{"freeradius": 1, "step-ca": 2}
			if data.Name == "cloud8021x.job.age" {
				want = map[string]float64{"inventory": 1, "outbox": 2}
			}
			for _, point := range points {
				attrs := point.Attributes.ToSlice()
				if len(attrs) != 1 || string(attrs[0].Key) != "component" || want[attrs[0].Value.AsString()] != point.Value {
					t.Fatal(point)
				}
			}
		}
	}
	if found != 3 {
		t.Fatalf("missing component measurements: %d", found)
	}
}

func TestSharedGaugesCarryClusterScope(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	defer func() { _ = provider.Shutdown(context.Background()) }()
	m := newMeasurements(provider.Meter("test"), &atomic.Uint64{})
	cluster := strings.Repeat("a", 64)
	m.ObserveCluster(context.Background(), "ledger.sessions", cluster, 3)
	m.ObserveCluster(context.Background(), "outbox.depth", "unknown", 4)
	var result metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &result); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, scope := range result.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name == "cloud8021x.outbox.depth" {
				t.Fatal("unknown cluster emitted shared gauge")
			}
			if m.Name == "cloud8021x.ledger.sessions" {
				for _, p := range m.Data.(metricdata.Gauge[float64]).DataPoints {
					found = true
					c, _ := p.Attributes.Value(attribute.Key("cluster"))
					s, _ := p.Attributes.Value(attribute.Key("scope"))
					if c.AsString() != cluster || s.AsString() != "shared" || p.Value != 3 {
						t.Fatal("shared gauge lost identity", p)
					}
				}
			}
		}
	}
	if !found {
		t.Fatal("shared gauge missing")
	}
}
