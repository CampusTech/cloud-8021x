package gcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEnabledVersionsOnlyEmptySuccessMeansAbsent(t *testing.T) {
	for _, status := range []int{200, 403, 404, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("filter") != "state=ENABLED" {
					t.Error("missing state filter")
				}
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{}`))
			}))
			defer s.Close()
			c := &Client{http: s.Client(), secretBase: s.URL, token: func(context.Context) (string, error) { return "fixture", nil }}
			v, e := c.Enabled(context.Background(), "projects/fixture-project/secrets/ca-root")
			if (e == nil) != (status == 200) {
				t.Fatalf("status %d error %v", status, e)
			}
			if len(v) != 0 {
				t.Fatal(v)
			}
		})
	}
}
func TestCloudSQLRejectsWrongModePinAndInstance(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"connectionName":"fixture-project:us-central1:ca","serverCaMode":"GOOGLE_MANAGED_CAS_CA","serverCaCert":{"cert":"public"}}`))
	}))
	defer s.Close()
	c := &Client{http: s.Client(), sqlBase: s.URL, token: func(context.Context) (string, error) { return "fixture", nil }}
	if c.VerifyInstanceCA(context.Background(), "fixture-project:us-central1:ca", "00") == nil {
		t.Fatal("shared CA accepted")
	}
}

func TestCanonicalProjectVersionsAndIntegrity(t *testing.T) {
	for _, project := range []string{"123456789", "987654321"} {
		t.Run(project, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, ":access") {
					_ = json.NewEncoder(w).Encode(map[string]any{"name": "projects/" + project + "/secrets/ca-root/versions/7", "payload": map[string]string{"data": base64.StdEncoding.EncodeToString([]byte("fixture")), "dataCrc32c": crc([]byte("fixture"))}})
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"versions": []any{map[string]string{"name": "projects/" + project + "/secrets/ca-root/versions/7", "state": "ENABLED"}}})
			}))
			defer s.Close()
			c := &Client{http: s.Client(), secretBase: s.URL, projectID: "fixture-project", projectNumber: "123456789", token: func(context.Context) (string, error) { return "fixture", nil }}
			v, e := c.Enabled(context.Background(), "projects/fixture-project/secrets/ca-root")
			if project != "123456789" {
				if e == nil {
					t.Fatal("foreign project accepted")
				}
				return
			}
			if e != nil || len(v) != 1 {
				t.Fatalf("canonical lookup %v", e)
			}
			if _, e = c.Access(context.Background(), v[0]); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestSecretPayloadRequiresExactNameAndCRC(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-name", "wrong-crc"} {
		t.Run(mode, func(t *testing.T) {
			name := "projects/fixture-project/secrets/test/versions/1"
			sum := crc([]byte("fixture"))
			if mode == "wrong-name" {
				name = "projects/fixture-project/secrets/other/versions/1"
			}
			if mode == "wrong-crc" {
				sum = "0"
			}
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"name": name, "payload": map[string]string{"data": "Zml4dHVyZQ==", "dataCrc32c": sum}})
			}))
			defer s.Close()
			c := &Client{http: s.Client(), secretBase: s.URL, token: func(context.Context) (string, error) { return "fixture", nil }}
			_, e := c.Access(context.Background(), "projects/fixture-project/secrets/test/versions/1")
			if (e == nil) != (mode == "valid") {
				t.Fatalf("%s: %v", mode, e)
			}
		})
	}
}
func TestCloudSQLCorrectInstanceCA(t *testing.T) {
	sum := sha256.Sum256([]byte("public"))
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"connectionName":"fixture-project:us-central1:ca","serverCaMode":"GOOGLE_MANAGED_INTERNAL_CA","serverCaCert":{"cert":"public"}}`))
	}))
	defer s.Close()
	c := &Client{http: s.Client(), sqlBase: s.URL, token: func(context.Context) (string, error) { return "fixture", nil }}
	if e := c.VerifyInstanceCA(context.Background(), "fixture-project:us-central1:ca", hex.EncodeToString(sum[:])); e != nil {
		t.Fatal(e)
	}
}
