package telemetry

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/otel/sdk/metric"
)

func TestCertificateSafetyMetricsRegistered(t *testing.T) {
	p := metric.NewMeterProvider()
	defer func() { _ = p.Shutdown(context.Background()) }()
	m := newMeasurements(p.Meter("test"), &atomic.Uint64{})
	for _, name := range []string{"certificate.days_until_expiry", "client_certificate.expiring_soon", "scep.decrypter_ready"} {
		if m.gauges[name] == nil {
			t.Errorf("retired safety producer missing %s", name)
		}
	}
}

func TestCertificateSafetyMetricsUnitsTagsAndExpiredValues(t *testing.T) {
	reader := metric.NewManualReader()
	p := metric.NewMeterProvider(metric.WithReader(reader), metric.WithResource(telemetryResource(Identity{Instance: "green-fixture-primary", Host: "green-fixture-primary", Environment: "fixture"})))
	defer func() { _ = p.Shutdown(context.Background()) }()
	m := newMeasurements(p.Meter("test"), &atomic.Uint64{})
	ctx := context.Background()
	m.CertificateExpiry(ctx, "freeradius", "server", "ec", -1)
	for _, ca := range []string{"ec", "rsa"} {
		for _, cert := range []string{"intermediate", "decrypter"} {
			m.CertificateExpiry(ctx, "step-ca", cert, ca, 2)
		}
	}
	m.CertificateExpiry(ctx, "step-ca", "private-subject", "rsa", 7)
	m.ClientExpiry(ctx, strings.Repeat("a", 64), 2)
	m.ClientExpiry(ctx, "unknown", 9)
	m.SCEPReady(ctx, false)
	initial := map[string]uint32{"start_time": 1}
	for _, name := range nativeCounterNames {
		initial[name] = 100
	}
	for _, name := range nativeGaugeNames {
		initial[name] = 2
	}
	m.NativeStatistics(initial)
	for _, name := range nativeCounterNames {
		initial[name] = 103
	}
	m.NativeStatistics(initial)
	var output metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &output); err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, scope := range output.ScopeMetrics {
		for _, series := range scope.Metrics {
			if !strings.Contains(series.Name, "certificate") && !strings.Contains(series.Name, "scep.") {
				continue
			}
			found[series.Name] = true
			points := series.Data.(metricdata.Gauge[float64]).DataPoints
			switch series.Name {
			case "cloud8021x.certificate.days_until_expiry":
				if series.Unit != "d" || len(points) != 5 {
					t.Fatal(series)
				}
				expired := false
				for _, point := range points {
					if point.Value < 0 {
						expired = true
					}
					if point.Attributes.Len() != 3 {
						t.Fatal("unbounded expiry tags")
					}
				}
				if !expired {
					t.Fatal("expired certificate omitted")
				}
			case "cloud8021x.client_certificate.expiring_soon":
				if series.Unit != "{certificate}" || len(points) != 1 || points[0].Value != 2 {
					t.Fatal(series)
				}
				window, _ := points[0].Attributes.Value("window")
				scope, _ := points[0].Attributes.Value("scope")
				if window.AsString() != "48h" || scope.AsString() != "shared" {
					t.Fatal("window/shared attribution lost")
				}
			case "cloud8021x.scep.decrypter_ready":
				if series.Unit != "1" || len(points) != 1 || points[0].Value != 0 {
					t.Fatal("degraded readiness not zero")
				}
			}
		}
	}
	if len(found) != 3 {
		t.Fatal("missing safety metric series", found)
	}
	if dir := os.Getenv("C8021X_MONITORING_FIXTURE_OUTPUT"); dir != "" {
		raw, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, "neutral-metrics.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
