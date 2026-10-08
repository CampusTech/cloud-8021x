package postgres

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/jobs"
)

// commitDropProxy is a development-only TLS PostgreSQL protocol relay. It
// forwards an actual COMMIT to PostgreSQL, receives the actual CommandComplete,
// then drops the connection before the client receives any commit response.
func commitDropProxy(t *testing.T, c config.Database) (string, *atomic.Bool) {
	t.Helper()
	target, _ := url.Parse(os.Getenv("C8021X_PG_TEST_DSN"))
	upstreamAddress := target.Host
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(os.Getenv("C8021X_PG_TEST_TLS_CERT"), os.Getenv("C8021X_PG_TEST_TLS_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	upstreamTLS, err := tlsConfig(c, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	drop := new(atomic.Bool)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var opened []net.Conn
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			down, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			opened = append(opened, down)
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { _ = down.Close() }()
				_ = down.SetDeadline(time.Now().Add(10 * time.Second))
				var ssl [8]byte
				if _, err := io.ReadFull(down, ssl[:]); err != nil || binary.BigEndian.Uint32(ssl[:4]) != 8 || binary.BigEndian.Uint32(ssl[4:]) != 80877103 {
					return
				}
				if _, err = down.Write([]byte{'S'}); err != nil {
					return
				}
				client := tls.Server(down, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}})
				if err = client.Handshake(); err != nil {
					return
				}
				up, err := net.DialTimeout("tcp", upstreamAddress, time.Second)
				if err != nil {
					return
				}
				defer func() { _ = up.Close() }()
				_ = up.SetDeadline(time.Now().Add(10 * time.Second))
				if _, err = up.Write(ssl[:]); err != nil {
					return
				}
				var response [1]byte
				if _, err = io.ReadFull(up, response[:]); err != nil || response[0] != 'S' {
					return
				}
				server := tls.Client(up, upstreamTLS.Clone())
				if err = server.Handshake(); err != nil {
					return
				}
				done := make(chan struct{})
				go func() { _, _ = io.Copy(server, client); _ = server.Close(); close(done) }()
				defer func() { _ = client.Close(); _ = server.Close(); <-done }()
				for {
					var header [5]byte
					if _, err = io.ReadFull(server, header[:]); err != nil {
						return
					}
					length := binary.BigEndian.Uint32(header[1:])
					if length < 4 || length > 1<<24 {
						return
					}
					body := make([]byte, length-4)
					if _, err = io.ReadFull(server, body); err != nil {
						return
					}
					if header[0] == 'C' && string(body) == "COMMIT\x00" && drop.CompareAndSwap(true, false) {
						return
					}
					if _, err = client.Write(append(header[:], body...)); err != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		for _, conn := range opened {
			_ = conn.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	target.Host = "localhost:" + fmtInt(int64(listener.Addr().(*net.TCPAddr).Port))
	target.User = url.UserPassword("app_runtime", "disposable-runtime")
	return target.String(), drop
}
func TestPostgresActualLostCommitResponse(t *testing.T) {
	admin, c := integration(t)
	reset(t, admin)
	ctx := context.Background()
	s := runtimeStore(t, admin, c)
	for _, status := range []string{"Start", "Interim-Update"} {
		if err := insertRaw(ctx, s, testRaw("lost-commit", status)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.ProcessOne(ctx, testKey, binding.MaxAge); err != nil {
		t.Fatal(err)
	}
	dsn, drop := commitDropProxy(t, c)
	proxied, err := New(ctx, dsn, c)
	if err != nil {
		t.Fatal(err)
	}
	defer proxied.Close()
	drop.Store(true)
	result, err := proxied.ProcessOne(ctx, testKey, binding.MaxAge)
	if err != nil || !result.Processed || drop.Load() {
		t.Fatal("lost commit not resolved", result, err)
	}
	if count(t, admin, "observations") != 2 || count(t, admin, "intervals") != 1 || count(t, admin, "work") != 3 {
		t.Fatal("lost response duplicated/lost atomic state")
	}
	if err = drain(ctx, proxied); err != nil {
		t.Fatal(err)
	}
	if count(t, admin, "intervals") != 1 {
		t.Fatal("retry duplicated interval")
	}
	if err = proxied.Reserve(ctx, "uncertain-submit", "certificate", json.RawMessage(`{"device":"d"}`)); err != nil {
		t.Fatal(err)
	}
	claim, err := proxied.Claim(ctx, "certificate", "worker", time.Minute)
	if err != nil || claim == nil {
		t.Fatal(claim, err)
	}
	drop.Store(true)
	if err = proxied.StartAttempt(ctx, *claim); !errors.Is(err, ErrUncertain) {
		t.Fatal("lost Start response not uncertain", err)
	}
	state, err := s.LookupWork(ctx, claim.ID)
	if err != nil || state.State != "started" {
		t.Fatal("persisted attempt lost", state, err)
	}
	if _, err = admin.pool.Exec(ctx, "UPDATE ledger.work SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1", claim.ID); err != nil {
		t.Fatal(err)
	}
	next, err := s.Claim(ctx, "certificate", "replacement", time.Minute)
	if err != nil || next != nil {
		t.Fatal("uncertain external submission resubmitted", next, err)
	}
	if err = s.FinishAttempt(ctx, *claim, jobs.Succeeded, json.RawMessage(`{}`)); !errors.Is(err, jobs.ErrFenced) {
		t.Fatal("dead process not fenced", err)
	}
}
