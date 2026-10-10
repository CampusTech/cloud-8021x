package telemetry

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var nativeCounterNames = []string{"total_access_requests", "total_access_challenges", "total_auth_duplicate_requests", "total_auth_malformed_requests", "total_auth_invalid_requests", "total_auth_dropped_requests", "total_acct_requests", "total_acct_responses"}
var nativeGaugeNames = []string{"queue_len_internal", "queue_len_auth", "queue_len_acct", "queue_pps_in", "queue_pps_out"}

type nativeMeasurements struct {
	sync.Mutex
	present    map[string]uint32
	previous   map[string]uint32
	cumulative map[string]int64
	start      uint32
}

func (x *Measurements) initNative(m metric.Meter) {
	n := &nativeMeasurements{present: map[string]uint32{}, previous: map[string]uint32{}, cumulative: map[string]int64{}}
	x.native = n
	counters := map[string]metric.Int64ObservableCounter{}
	gauges := map[string]metric.Int64ObservableGauge{}
	var instruments []metric.Observable
	for _, name := range nativeCounterNames {
		c, _ := m.Int64ObservableCounter("cloud8021x.radius."+name, metric.WithUnit("{packet}"))
		counters[name] = c
		instruments = append(instruments, c)
	}
	for _, name := range nativeGaugeNames {
		unit := "{packet}"
		if name == "queue_pps_in" || name == "queue_pps_out" {
			unit = "{packet}/s"
		}
		g, _ := m.Int64ObservableGauge("cloud8021x.radius."+name, metric.WithUnit(unit))
		gauges[name] = g
		instruments = append(instruments, g)
	}
	_, _ = m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		n.Lock()
		defer n.Unlock()
		attrs := metric.WithAttributes(attribute.String("component", "freeradius"))
		for name, c := range counters {
			if _, ok := n.present[name]; ok && n.start != 0 {
				o.ObserveInt64(c, n.cumulative[name], attrs)
			}
		}
		for name, g := range gauges {
			if v, ok := n.present[name]; ok {
				o.ObserveInt64(g, int64(v), attrs)
			}
		}
		return nil
	}, instruments...)
}

// NativeStatistics establishes an initial baseline, then accumulates only
// observed forward deltas. Restart/wrap/decrease starts a new baseline without
// inventing traffic. Unavailable samples clear current series until observed.
func (x *Measurements) NativeStatistics(values map[string]uint32) {
	n := x.native
	n.Lock()
	defer n.Unlock()
	start := values["start_time"]
	for _, name := range nativeCounterNames {
		value, ok := values[name]
		previous, known := n.previous[name]
		if ok && known && start != 0 && start == n.start && value >= previous {
			n.cumulative[name] += int64(value - previous)
		}
	}
	n.start = start
	n.present = map[string]uint32{}
	n.previous = map[string]uint32{}
	for _, name := range append(append([]string{}, nativeCounterNames...), nativeGaugeNames...) {
		if value, ok := values[name]; ok {
			n.present[name] = value
			n.previous[name] = value
		}
	}
}
