package telemetry

import (
	"context"
	"sync/atomic"
	"testing"

	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestNativeCountersBaselineResetAndUnavailable(t *testing.T) {
	reader := metric.NewManualReader()
	p := metric.NewMeterProvider(metric.WithReader(reader))
	defer func() { _ = p.Shutdown(context.Background()) }()
	m := newMeasurements(p.Meter("test"), &atomic.Uint64{})
	for _, step := range []struct {
		values  map[string]uint32
		want    int64
		present bool
	}{
		{nil, 0, false},
		{map[string]uint32{"start_time": 100, "total_access_requests": 200}, 0, true},
		{map[string]uint32{"start_time": 100, "total_access_requests": 207}, 7, true},
		{map[string]uint32{"start_time": 101, "total_access_requests": 3}, 7, true},
		{map[string]uint32{"start_time": 101, "total_access_requests": 5}, 9, true},
		{map[string]uint32{"start_time": 101, "total_access_requests": 1}, 9, true},
		{nil, 0, false},
		{map[string]uint32{"start_time": 101, "total_access_requests": 1000}, 9, true},
		{map[string]uint32{"start_time": 101, "total_access_requests": 1002}, 11, true},
	} {
		m.NativeStatistics(step.values)
		var output metricdata.ResourceMetrics
		if err := reader.Collect(context.Background(), &output); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, scope := range output.ScopeMetrics {
			for _, series := range scope.Metrics {
				if series.Name != "cloud8021x.radius.total_access_requests" {
					continue
				}
				sum := series.Data.(metricdata.Sum[int64])
				if len(sum.DataPoints) == 0 {
					continue
				}
				found = true
				if !sum.IsMonotonic || sum.DataPoints[0].Value != step.want || series.Unit != "{packet}" {
					t.Fatal("invented native counter delta", sum, step)
				}
			}
		}
		if found != step.present {
			t.Fatal("missing native counter fabricated observation", found, step)
		}
	}
}
