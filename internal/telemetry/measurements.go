package telemetry

import (
	"context"
	"math"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Measurements accepts fixed metric names and bounded categories; missing native
// status is omitted, never represented as a fabricated successful delivery.
type Measurements struct {
	gauges   map[string]metric.Float64Gauge
	duration metric.Float64Histogram
	active   metric.Int64UpDownCounter
	retries  metric.Int64Counter
}

func newMeasurements(m metric.Meter, failures *atomic.Uint64) *Measurements {
	x := &Measurements{gauges: map[string]metric.Float64Gauge{}}
	for _, n := range []string{"backend.up", "backend.uptime", "spool.files", "spool.bytes", "spool.oldest_age", "spool.free_bytes", "native.write_failures", "native.replay_failures", "inventory.age", "source.age", "ledger.sessions", "ledger.intake", "ledger.quarantine", "outbox.depth", "outbox.oldest_age", "usage.age", "job.age", "claim.errors", "export.errors"} {
		x.gauges[n], _ = m.Float64Gauge("cloud8021x." + n)
	}
	x.duration, _ = m.Float64Histogram("cloud8021x.operation.duration", metric.WithUnit("s"))
	x.active, _ = m.Int64UpDownCounter("cloud8021x.operation.active")
	x.retries, _ = m.Int64Counter("cloud8021x.api.retries")
	uptime, _ := m.Float64ObservableGauge("cloud8021x.process.uptime", metric.WithUnit("s"))
	heap, _ := m.Int64ObservableGauge("cloud8021x.process.heap", metric.WithUnit("By"))
	goroutines, _ := m.Int64ObservableGauge("cloud8021x.process.goroutines")
	gc, _ := m.Int64ObservableCounter("cloud8021x.process.gc")
	exports, _ := m.Int64ObservableCounter("cloud8021x.telemetry.errors")
	start := time.Now()
	_, _ = m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		o.ObserveFloat64(uptime, time.Since(start).Seconds())
		o.ObserveInt64(heap, int64(mem.HeapAlloc))
		o.ObserveInt64(goroutines, int64(runtime.NumGoroutine()))
		o.ObserveInt64(gc, int64(mem.NumGC))
		o.ObserveInt64(exports, int64(failures.Load()))
		return nil
	}, uptime, heap, goroutines, gc, exports)
	return x
}
func (x *Measurements) Observe(ctx context.Context, name string, value float64) {
	if name == "backend.up" || name == "backend.uptime" || name == "job.age" {
		return
	}
	if g := x.gauges[name]; g != nil && value >= 0 && !math.IsInf(value, 0) {
		g.Record(ctx, value)
	}
}
func operation(v string) string {
	switch v {
	case "policy", "webhook", "broker", "inventory", "network", "certificate", "bootstrap", "accounting", "claim", "usage", "outbox", "fleet", "unifi", "meraki":
		return v
	default:
		return "other"
	}
}
func (x *Measurements) Retry(ctx context.Context, backend string) {
	x.retries.Add(ctx, 1, metric.WithAttributes(attribute.String("operation", operation(backend))))
}

// ObserveComponent records only fixed backend/job categories. Negative or nonfinite
// values mean unavailable and are omitted; unknown labels never create a series.
func (x *Measurements) ObserveComponent(ctx context.Context, name, component string, value float64) {
	if value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
		return
	}
	switch name {
	case "backend.up", "backend.uptime":
		switch component {
		case "freeradius", "step-ca", "postgres", "collector":
		default:
			return
		}
	case "job.age":
		switch component {
		case "inventory", "certificates", "sites", "sources", "accounting", "usage", "outbox", "metrics":
		default:
			return
		}
	default:
		return
	}
	x.gauges[name].Record(ctx, value, metric.WithAttributes(attribute.String("component", component)))
}

// ObserveCluster marks shared PostgreSQL observations explicitly. Dashboard
// aliases use max by cluster (across node resources), never sum both reporters.
// The protected transition is common to both nodes and contains no credentials.
func (x *Measurements) ObserveCluster(ctx context.Context, name, cluster string, value float64) {
	switch name {
	case "ledger.sessions", "ledger.intake", "ledger.quarantine", "outbox.depth", "outbox.oldest_age", "usage.age":
		if len(cluster) != 64 || strings.Trim(cluster, "0123456789abcdef") != "" || value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
			return
		}
		if g := x.gauges[name]; g != nil {
			g.Record(ctx, value, metric.WithAttributes(attribute.String("scope", "shared"), attribute.String("cluster", cluster)))
		}
	default:
		x.Observe(ctx, name, value)
	}
}
