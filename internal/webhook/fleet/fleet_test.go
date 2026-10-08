package fleet

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLookupHostByIdentity_Found(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/latest/fleet/hosts/identifier/SERIAL123" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"host":{"id":733,"hardware_serial":"SERIAL123","platform":"darwin","labels":[{"name":"All Hosts"},{"name":"test-pilots"}],"mdm":{"enrollment_status":"On (manual)"}}}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "test-token", 5*time.Second)
	h, err := c.LookupHostByIdentity(context.Background(), "SERIAL123")
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

func TestLookupHostByIdentity_NotEnrolled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"host":{"id":733,"hardware_serial":"SERIAL123","platform":"windows","labels":[{"name":"All Hosts"}],"mdm":{"enrollment_status":"Off"}}}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "test-token", 5*time.Second)
	h, err := c.LookupHostByIdentity(context.Background(), "SERIAL123")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil host for a present-but-unenrolled record")
	}
	if h.Enrolled {
		t.Fatal("expected Enrolled false for enrollment_status Off")
	}
}

func TestLookupHostByIdentity_PendingNotEnrolled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"host":{"id":733,"hardware_serial":"SERIAL123","platform":"windows","labels":[{"name":"All Hosts"}],"mdm":{"enrollment_status":"Pending"}}}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "test-token", 5*time.Second)
	h, err := c.LookupHostByIdentity(context.Background(), "SERIAL123")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil host for a present-but-pending record")
	}
	if h.Enrolled {
		t.Fatal("expected Enrolled false for enrollment_status Pending")
	}
}

func TestLookupHostByIdentity_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := New(srv.URL, "test-token", 5*time.Second)
	h, err := c.LookupHostByIdentity(context.Background(), "NOPE")
	if err != nil {
		t.Fatalf("not-found should be a clean (nil host, nil err) signal, got err: %v", err)
	}
	if h != nil {
		t.Fatalf("expected nil host for not-found, got %#v", h)
	}
}

func TestLookupHostByIdentity_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := New(srv.URL, "test-token", 5*time.Second)
	_, err := c.LookupHostByIdentity(context.Background(), "X")
	if err == nil {
		t.Fatal("5xx must be an error so the caller fails closed")
	}
}

func TestLookupHostByIdentity_BYODAndExactMatch(t *testing.T) {
	const enrollment = "01234567-89ab-cdef-0123-456789abcdef"
	for _, tc := range []struct {
		name, identity, response string
		want                     bool
	}{
		{"byod enrollment", enrollment, `{"host":{"id":42,"uuid":"` + enrollment + `","hardware_serial":"","mdm":{"enrollment_status":"On (personal)"}}}`, true},
		{"uuid case", "01234567-89AB-CDEF-0123-456789ABCDEF", `{"host":{"id":42,"uuid":"` + enrollment + `","mdm":{"enrollment_status":"On (personal)"}}}`, true},
		{"hostname collision", "chosen-name", `{"host":{"id":42,"hostname":"chosen-name","uuid":"different","hardware_serial":"SERIAL","mdm":{"enrollment_status":"On (manual)"}}}`, false},
		{"wrong host", enrollment, `{"host":{"id":42,"uuid":"different","hardware_serial":"SERIAL","mdm":{"enrollment_status":"On (manual)"}}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/latest/fleet/hosts/identifier/"+tc.identity {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				_, _ = w.Write([]byte(tc.response))
			}))
			defer srv.Close()
			host, err := New(srv.URL, "token", time.Second).LookupHostByIdentity(context.Background(), tc.identity)
			if err != nil {
				t.Fatal(err)
			}
			if (host != nil) != tc.want {
				t.Fatalf("got host %v, want found=%v", host, tc.want)
			}
		})
	}
}
