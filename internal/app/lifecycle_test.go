package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestLifecycleAtomicBindBeforeJobs(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = occupied.Close() }()
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := first.Addr().String()
	_ = first.Close()
	var runs atomic.Int32
	l := lifecycle{Servers: []*http.Server{{Addr: address}, {Addr: occupied.Addr().String()}}, Jobs: []scheduledJob{{Name: "test", Interval: time.Millisecond, Timeout: time.Second, Run: func(context.Context) error { runs.Add(1); return nil }}}}
	if err := l.Run(context.Background()); err == nil {
		t.Fatal("partial listener startup succeeded")
	}
	if runs.Load() != 0 {
		t.Fatal("job ran before atomic binding")
	}
	rebound, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal("bound listener leaked", err)
	}
	_ = rebound.Close()
}
func TestLifecycleCancellationAndIndependentWorkers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	blocked := make(chan struct{})
	progressed := make(chan struct{})
	stopped := make(chan struct{})
	notified := make(chan struct{})
	l := lifecycle{Servers: []*http.Server{{Addr: "127.0.0.1:0", Handler: http.NewServeMux()}}, StopTimeout: time.Second, Ready: func(context.Context) error { return nil }, Notify: func(s string) error {
		if s == "READY=1" {
			close(notified)
		}
		return nil
	}, Jobs: []scheduledJob{
		{Name: "blocked", Interval: time.Millisecond, Timeout: time.Second, Run: func(ctx context.Context) error { close(blocked); <-ctx.Done(); close(stopped); return ctx.Err() }},
		{Name: "independent", Interval: time.Hour, Timeout: time.Second, Run: func(context.Context) error { close(progressed); return nil }}}}
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()
	for _, ch := range []chan struct{}{blocked, progressed, notified} {
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatal("separate job blocked")
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("unbounded cancellation")
	}
	<-stopped
}
func TestLifecycleNeverNotifiesUnready(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	var notified atomic.Bool
	l := lifecycle{Servers: []*http.Server{{Addr: "127.0.0.1:0"}}, Ready: func(context.Context) error { return errors.New("stale inventory") }, Notify: func(s string) error {
		if s == "READY=1" {
			notified.Store(true)
		}
		return nil
	}}
	_ = l.Run(ctx)
	if notified.Load() {
		t.Fatal("unready startup announced READY")
	}
}
func TestScheduleErrorsBackOffAndNeverOverlap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	var runs atomic.Int32
	runScheduled(ctx, scheduledJob{Name: "failing", Interval: 20 * time.Millisecond, Timeout: time.Second, Run: func(context.Context) error { runs.Add(1); return errors.New("offline") }}, nil)
	if n := runs.Load(); n < 1 || n > 3 {
		t.Fatalf("busy loop: %d", n)
	}
}
