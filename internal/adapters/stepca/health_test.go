package stepca

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLocalHealthRequiresPinnedTLSAndOKResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"status":"ok"}`)) }))
	defer server.Close()
	roots := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	address := strings.TrimPrefix(server.URL, "https://")
	if err := ProbeHealth(context.Background(), address, "example.com", roots); err != nil {
		t.Fatal(err)
	}
	if err := ProbeHealth(context.Background(), address, "wrong.example", roots); err == nil {
		t.Fatal("wrong certificate identity accepted")
	}
	if err := ProbeHealth(context.Background(), address, "example.com", nil); err == nil {
		t.Fatal("missing trust accepted")
	}
	if err := ProbeHealth(context.Background(), "192.0.2.1:8443", "example.com", roots); err == nil {
		t.Fatal("nonlocal probe accepted")
	}
}
