package broker

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/webhook/internal/challenge"
)

const testKey = "0123456789abcdef0123456789abcdef"
const fleetBody = `{"webhook":{"id":1,"webhookEvent":"SCEPChallenge","eventTimestamp":1800000000,"name":"SCEPChallenge"},"event":{"scepServerUrl":"https://scep.example/scep/wifi-scep","payloadIdentifier":"cdb0bc64-f3eb-4b1a-aa5e-9a5d994ca593","payloadTypes":["com.apple.security.scep"]}}`

func TestFleetNativeContract(t *testing.T) {
	h, err := New(Options{Username: "fleet", Token: testKey, SigningKey: testKey, SCEPURL: "https://scep.example/scep/wifi-scep", Provisioner: "wifi-scep"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/fleet/scep-challenge", strings.NewReader(fleetBody))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("fleet", testKey)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("Fleet configuration probe failed: %d %s", w.Code, w.Body)
	}
	if !challenge.VerifyInventory([]byte(testKey), w.Body.String(), "wifi-scep", time.Now()) {
		t.Fatal("Fleet expects an unquoted challenge body without a trailing newline")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("challenge response must not be cached")
	}
}

func TestBrokerRejectsInvalidRequests(t *testing.T) {
	h, err := New(Options{Username: "fleet", Token: testKey, SigningKey: testKey, SCEPURL: "https://scep.example/scep/wifi-scep", Provisioner: "wifi-scep"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, method, path, body, user, password, contentType string
		want                                                  int
	}{
		{"missing auth", "POST", "/fleet/scep-challenge", fleetBody, "", "", "application/json", 401},
		{"wrong password", "POST", "/fleet/scep-challenge", fleetBody, "fleet", "incorrect", "application/json", 401},
		{"wrong username", "POST", "/fleet/scep-challenge", fleetBody, "other", testKey, "application/json", 401},
		{"wrong URL", "POST", "/fleet/scep-challenge", strings.Replace(fleetBody, "scep.example", "evil.example", 1), "fleet", testKey, "application/json", 400},
		{"bad payload", "POST", "/fleet/scep-challenge", strings.Replace(fleetBody, "com.apple.security.scep", "com.apple.security.root", 1), "fleet", testKey, "application/json", 400},
		{"bad event", "POST", "/fleet/scep-challenge", strings.Replace(fleetBody, "SCEPChallenge", "other", 1), "fleet", testKey, "application/json", 400},
		{"bad JSON", "POST", "/fleet/scep-challenge", "{", "fleet", testKey, "application/json", 400},
		{"trailing JSON", "POST", "/fleet/scep-challenge", fleetBody + "{}", "fleet", testKey, "application/json", 400},
		{"oversize", "POST", "/fleet/scep-challenge", fleetBody + strings.Repeat(" ", 65536), "fleet", testKey, "application/json", 413},
		{"wrong media", "POST", "/fleet/scep-challenge", fleetBody, "fleet", testKey, "text/plain", 415},
		{"wrong method", "GET", "/fleet/scep-challenge", fleetBody, "fleet", testKey, "application/json", 405},
		{"authorize not public", "POST", "/authorize", fleetBody, "fleet", testKey, "application/json", 404},
		{"step hook not public", "POST", "/scep-challenge", fleetBody, "fleet", testKey, "application/json", 404},
		{"health", "GET", "/healthz", "", "", "", "", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.contentType)
			if tc.user != "" {
				req.SetBasicAuth(tc.user, tc.password)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.want, w.Body)
			}
		})
	}
}
