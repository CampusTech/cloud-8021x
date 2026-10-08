package httpjson

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBounded429AndCancellation(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "0")
		http.Error(w, "SENTINEL-SECRET", http.StatusTooManyRequests)
	}))
	defer s.Close()
	c, e := New(s.URL, "X-API-Key", "synthetic", s.Client(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	var out any
	_, e = c.Get(context.Background(), c.URL("/read"), &out)
	if e == nil || calls.Load() != 3 || strings.Contains(e.Error(), "SENTINEL") {
		t.Fatalf("unbounded/leaked %v %d", e, calls.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = c.Get(ctx, c.URL("/read"), &out)
	if !errors.Is(e, context.Canceled) || calls.Load() != 3 {
		t.Fatal("cancelled read reached vendor")
	}
}
func TestRedirectAndPaginationCredentialConfinement(t *testing.T) {
	var targetCalls atomic.Int32
	evil := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls.Add(1) }))
	defer evil.Close()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, evil.URL+"/read", http.StatusFound) }))
	defer s.Close()
	c, _ := New(s.URL, "Authorization", "Bearer synthetic", s.Client(), time.Second)
	var out any
	if _, e := c.Get(context.Background(), c.URL("/read"), &out); e == nil {
		t.Fatal("redirect accepted")
	}
	if targetCalls.Load() != 0 {
		t.Fatal("credential escaped")
	}
	for _, next := range []string{evil.URL + "/read", s.URL + "/other", s.URL + "/read#fragment", s.URL + "/read?q=next>; rel=next, <" + s.URL + "/read?q=third"} {
		h := http.Header{"Link": []string{"<" + next + ">; rel=next"}}
		if _, e := Next(h, s.URL+"/read"); e == nil {
			t.Fatalf("hostile link accepted: %s", next)
		}
	}
}
