package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type scheduledJob struct {
	Name              string
	Interval, Timeout time.Duration
	Run               func(context.Context) error
}

// A job never overlaps itself; other jobs have independent goroutines, deadlines,
// and backoffs. Durable provider-specific claims remain inside Run.
func runScheduled(ctx context.Context, job scheduledJob, logger *logrus.Logger) {
	delay := time.Duration(0)
	failures := 0
	for {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if ctx.Err() != nil {
			return
		}
		call, cancel := context.WithTimeout(ctx, job.Timeout)
		err := job.Run(call)
		cancel()
		delay = job.Interval
		if err != nil {
			failures = min(failures+1, 6)
			delay = min(job.Interval*time.Duration(1<<failures), 5*time.Minute)
			if logger != nil && ctx.Err() == nil {
				logger.WithFields(logrus.Fields{"job": job.Name, "retry_after_seconds": delay.Seconds()}).Warn("background dependency unavailable")
			}
		} else {
			failures = 0
		}
	}
}

type lifecycle struct {
	Servers     []*http.Server
	Jobs        []scheduledJob
	Ready       func(context.Context) error
	Notify      func(string) error
	Flush       func(context.Context) error
	Logger      *logrus.Logger
	StopTimeout time.Duration
}

// Run publishes no readiness and starts no work until every port is owned. TLS
// certificates are loaded by construction, before any listener or worker exists.
func (l lifecycle) Run(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	listeners := make([]net.Listener, 0, len(l.Servers))
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	for _, server := range l.Servers {
		listener, err := net.Listen("tcp", server.Addr)
		if err != nil {
			return fmt.Errorf("bind daemon listener: %w", err)
		}
		if server.TLSConfig != nil {
			listener = tls.NewListener(listener, server.TLSConfig)
		}
		listeners = append(listeners, listener)
	}
	for _, j := range l.Jobs {
		if j.Run == nil || j.Interval <= 0 || j.Timeout <= 0 {
			return errors.New("invalid bounded schedule")
		}
	}
	results := make(chan error, len(l.Servers))
	for i, server := range l.Servers {
		go func() {
			err := server.Serve(listeners[i])
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			results <- err
		}()
	}
	timeout := l.StopTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	var workers sync.WaitGroup
	var result error
	// Refresh jobs may repair an initially missing/stale generation. They are never
	// prerequisites for serving requests against the existing local snapshot.
	for _, job := range l.Jobs {
		workers.Add(1)
		go func() { defer workers.Done(); runScheduled(ctx, job, l.Logger) }()
	}
	ready := false
	startup := time.NewTimer(25 * time.Second)
	defer startup.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	checkReady := func() error {
		if l.Ready == nil {
			return nil
		}
		call, stop := context.WithTimeout(ctx, time.Second)
		defer stop()
		return l.Ready(call)
	}
	for {
		if !ready && checkReady() == nil {
			if l.Notify != nil {
				if err := l.Notify("READY=1"); err != nil {
					result = err
					break
				}
			}
			ready = true
		}
		select {
		case <-ctx.Done():
		case result = <-results:
			if result == nil {
				result = errors.New("daemon listener stopped unexpectedly")
			}
		case <-startup.C:
			if !ready {
				result = errors.New("local policy or certificate readiness unavailable")
			} else {
				continue
			}
		case <-tick.C:
			continue
		}
		break
	}
	cancel()
	if l.Notify != nil {
		_ = l.Notify("STOPPING=1")
	}
	stop, stopCancel := context.WithTimeout(context.Background(), timeout)
	defer stopCancel()
	for _, server := range l.Servers {
		if err := server.Shutdown(stop); err != nil {
			_ = server.Close()
			result = errors.Join(result, err)
		}
	}
	stopped := make(chan struct{})
	go func() { workers.Wait(); close(stopped) }()
	select {
	case <-stopped:
	case <-stop.Done():
		result = errors.Join(result, errors.New("workers exceeded shutdown deadline"))
	}
	if l.Flush != nil {
		result = errors.Join(result, l.Flush(stop))
	}
	return result
}

func systemdNotify(message string) error {
	address := os.Getenv("NOTIFY_SOCKET")
	if address == "" {
		return nil
	}
	if !strings.HasPrefix(address, "/") && !strings.HasPrefix(address, "@") {
		return errors.New("invalid notification socket")
	}
	c, err := net.DialTimeout("unixgram", address, time.Second)
	if err != nil {
		return errors.New("readiness notification unavailable")
	}
	defer func() { _ = c.Close() }()
	if err = c.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	_, err = c.Write([]byte(message))
	return err
}
