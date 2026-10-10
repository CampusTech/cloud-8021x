package app

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestServeServersSurfacesListenerFailure(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = occupied.Close() }()
	servers := []*http.Server{{Addr: "127.0.0.1:0"}, {Addr: occupied.Addr().String()}}
	err = serveServers(context.Background(), servers, "missing.crt", "missing.key")
	if err == nil || !strings.Contains(err.Error(), "listen") {
		t.Fatalf("expected listener failure, got %v", err)
	}
}

func TestServeServersSurfacesCertificateFailure(t *testing.T) {
	err := serveServers(context.Background(), []*http.Server{{Addr: "127.0.0.1:0"}, {Addr: "127.0.0.1:0"}}, "missing.crt", "missing.key")
	if err == nil || !strings.Contains(err.Error(), "missing.crt") {
		t.Fatalf("expected TLS certificate failure, got %v", err)
	}
}

func TestServeServersShutsDownBothHTTPSListeners(t *testing.T) {
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	fixture.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addresses := make(chan string, 2)
	var servers []*http.Server
	for range 2 {
		servers = append(servers, &http.Server{Addr: "127.0.0.1:0", TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: fixture.TLS.Certificates}, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }), BaseContext: func(listener net.Listener) context.Context { addresses <- listener.Addr().String(); return ctx }})
	}
	done := make(chan error, 1)
	go func() { done <- serveServers(ctx, servers, "", "") }()
	for range 2 {
		select {
		case addr := <-addresses:
			response, err := fixture.Client().Get("https://" + addr)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != 200 {
				t.Fatalf("HTTPS listener returned %d", response.StatusCode)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("listeners did not start")
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("listeners did not shut down")
	}
}
