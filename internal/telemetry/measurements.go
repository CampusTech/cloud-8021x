package telemetry

import (
	"context"
	"runtime"
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
	if g := x.gauges[name]; g != nil && value >= 0 {
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
