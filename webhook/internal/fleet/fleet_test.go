package fleet

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLookupHostBySerial_Found(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/latest/fleet/hosts/identifier/SERIAL123" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"host":{"id":733,"hardware_serial":"SERIAL123","platform":"darwin","labels":[{"name":"All Hosts"},{"name":"test-pilots"}]}}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "test-token", 5*time.Second)
	h, err := c.LookupHostBySerial(context.Background(), "SERIAL123")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !h.Enrolled {
		t.Fatal("expected enrolled")
	}
	if h.Platform != "darwin" {
		t.Fatalf("platform: %s", h.Platform)
	}
	if !h.HasLabel("test-pilots") {
		t.Fatal("expected test-pilots label")
	}
}

func TestLookupHostBySerial_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := New(srv.URL, "test-token", 5*time.Second)
	h, err := c.LookupHostBySerial(context.Background(), "NOPE")
	if err != nil {
		t.Fatalf("not-found should be a clean (nil host, nil err) signal, got err: %v", err)
	}
	if h != nil {
		t.Fatalf("expected nil host for not-found, got %#v", h)
	}
}

func TestLookupHostBySerial_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := New(srv.URL, "test-token", 5*time.Second)
	_, err := c.LookupHostBySerial(context.Background(), "X")
	if err == nil {
		t.Fatal("5xx must be an error so the caller fails closed")
	}
}
