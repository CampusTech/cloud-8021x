package broker

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/webhook/internal/challenge"
)

// This is the expression in stock Fleet ee/server/service/scep/scep_proxy.go.
var fleetNDESChallengeRegex = regexp.MustCompile(`(?i)The enrollment challenge password is: <B> (?P<password>\S*)`)

func TestFleetNDESContractAndCacheWindow(t *testing.T) {
	h, err := New(Options{Username: "fleet", Token: testKey, SigningKey: testKey, SCEPURL: "https://scep.example/scep/wifi-scep", Provisioner: "wifi-scep"})
	if err != nil {
		t.Fatal(err)
	}
	var previous string
	for range 32 {
		req := httptest.NewRequest(http.MethodGet, "/fleet/ndes-challenge", nil)
		req.SetBasicAuth("fleet", testKey)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", w.Code, w.Body)
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Type") != "text/html; charset=utf-8" {
			t.Fatalf("unexpected headers: %v", w.Header())
		}
		matches := fleetNDESChallengeRegex.FindStringSubmatch(w.Body.String())
		if len(matches) != 2 {
			t.Fatal("response does not match Fleet's NDES parser")
		}
		token := matches[1]
		if !strings.HasPrefix(token, "v3.") || !regexp.MustCompile(`^[A-Za-z0-9+/.=-]+$`).MatchString(token) {
			t.Fatalf("bad NDES token: %q", token)
		}
		if token == previous {
			t.Fatal("fresh challenge requests reused a nonce")
		}
		previous = token
		for _, offset := range []time.Duration{0, 15 * time.Minute, 57 * time.Minute, 59 * time.Minute} {
			if !challenge.VerifyInventory([]byte(testKey), token, "wifi-scep", time.Now().Add(offset)) {
				t.Fatalf("NDES challenge rejected inside Fleet cache/issuance window: %s", offset)
			}
		}
		if challenge.VerifyInventory([]byte(testKey), token, "wifi-scep", time.Now().Add(time.Hour)) {
			t.Fatal("expired NDES token accepted")
		}
		if challenge.Verify([]byte(testKey), token, "staff", "wifi-scep", time.Now()) {
			t.Fatal("NDES token accepted by identity-bound verifier")
		}
	}
}

func TestFleetNDESRequiresBasicAuthentication(t *testing.T) {
	h, err := New(Options{Username: "fleet", Token: testKey, SigningKey: testKey, SCEPURL: "https://scep.example/scep/wifi-scep", Provisioner: "wifi-scep"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, user, password string }{
		{"anonymous", "", ""}, {"wrong user", "other", testKey}, {"wrong password", "fleet", "invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/fleet/ndes-challenge", nil)
			if tc.user != "" {
				req.SetBasicAuth(tc.user, tc.password)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != `Basic realm="fleet-scep"` {
				t.Fatalf("Fleet NTLM negotiator requires Basic challenge: %d %v", w.Code, w.Header())
			}
			if w.Header().Get("Cache-Control") != "no-store" || fleetNDESChallengeRegex.Match(w.Body.Bytes()) {
				t.Fatal("unauthenticated response cached or disclosed challenge")
			}
		})
	}
	req := httptest.NewRequest(http.MethodPost, "/fleet/ndes-challenge", nil)
	req.SetBasicAuth("fleet", testKey)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status=%d", w.Code)
	}
}
