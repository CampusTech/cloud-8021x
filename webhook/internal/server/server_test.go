package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/webhook/internal/authorize"
	"github.com/CampusTech/cloud-8021x/webhook/internal/challenge"
	"github.com/CampusTech/cloud-8021x/webhook/internal/fleet"
)

func sigOf(secret, body string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(body))
	return hex.EncodeToString(m.Sum(nil))
}

func TestHandler(t *testing.T) {
	secret := "sec"
	body := `{"attestationData":{"permanentIdentifier":"S1"}}`

	h := New(secret, "", DeciderFunc(func(serial string) bool { return serial == "S1" }))
	srv := httptest.NewServer(h)
	defer srv.Close()

	post := func(b, sig string) ResponseShape {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/authorize", strings.NewReader(b))
		if sig != "" {
			req.Header.Set("X-Smallstep-Signature", sig)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var rs ResponseShape
		_ = json.NewDecoder(resp.Body).Decode(&rs)
		return rs
	}

	if rs := post(body, sigOf(secret, body)); !rs.Allow {
		t.Fatal("expected allow for good sig + known serial")
	}
	if rs := post(body, sigOf("wrong", body)); rs.Allow {
		t.Fatal("bad signature must deny")
	}
	if rs := post(body, ""); rs.Allow {
		t.Fatal("missing signature must deny")
	}
	unk := `{"attestationData":{"permanentIdentifier":"NOPE"}}`
	if rs := post(unk, sigOf(secret, unk)); rs.Allow {
		t.Fatal("unknown serial must deny")
	}
	bad := `{not json`
	if rs := post(bad, sigOf(secret, bad)); rs.Allow {
		t.Fatal("malformed body must deny")
	}
}

// Knowing a deployment-wide SCEP password must never authorize a requester to
// choose another enrolled device's CN (and therefore that device's VLAN).
func TestSCEPRejectsSharedChallengeImpersonation(t *testing.T) {
	const shared = "shared-upstream-password-known-to-byod-device"
	h := New("webhook-secret", shared, DeciderFunc(func(identity string) bool {
		return identity == "staff-device" || identity == "byod-device"
	}))
	body := `{"provisionerName":"wifi-scep","scepChallenge":"` + shared + `","x509CertificateRequest":{"subject":{"commonName":"staff-device"}}}`
	req := httptest.NewRequest(http.MethodPost, "/scep-challenge", strings.NewReader(body))
	req.Header.Set("X-Smallstep-Signature", sigOf("webhook-secret", body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var result ResponseShape
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Allow {
		t.Fatal("a shared challenge allowed a BYOD requester to impersonate an enrolled staff device")
	}
}

const challengeKey = "0123456789abcdef0123456789abcdef"

func issueChallenge(t *testing.T, identity string, now time.Time) string {
	t.Helper()
	token, err := challenge.Issue([]byte(challengeKey), identity, "wifi-scep", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func scepBody(t *testing.T, identity, token, provisioner string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"scepChallenge": token, "provisionerName": provisioner,
		"x509CertificateRequest": map[string]any{"subject": map[string]string{"commonName": identity}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestSCEPChallengeHandler(t *testing.T) {
	const identity = "FRAGAACPA74412000D"
	token := issueChallenge(t, identity, time.Now())
	expired := issueChallenge(t, identity, time.Now().Add(-2*time.Hour))
	future := issueChallenge(t, identity, time.Now().Add(time.Hour))
	for _, tc := range []struct {
		name, key, token, identity, provisioner, signingSecret string
		enrolled, want                                         bool
	}{
		{"enrolled serial", challengeKey, token, identity, "wifi-scep", "sec", true, true},
		{"legacy suffix", challengeKey, token, identity + " Campus WiFi", "wifi-scep", "sec", true, true},
		{"repeated suffix is a different identity", challengeKey, token, identity + " Campus WiFi Campus WiFi", "wifi-scep", "sec", true, false},
		{"wrong identity", challengeKey, token, "OTHER-ENROLLED-DEVICE", "wifi-scep", "sec", true, false},
		{"wrong provisioner", challengeKey, token, identity, "other-scep", "sec", true, false},
		{"missing provisioner", challengeKey, token, identity, "", "sec", true, false},
		{"unenrolled", challengeKey, token, identity, "wifi-scep", "sec", false, false},
		{"invalid challenge", challengeKey, "nope", identity, "wifi-scep", "sec", true, false},
		{"expired", challengeKey, expired, identity, "wifi-scep", "sec", true, false},
		{"future token", challengeKey, future, identity, "wifi-scep", "sec", true, false},
		{"bad webhook signature", challengeKey, token, identity, "wifi-scep", "wrong", true, false},
		{"missing key", "", token, identity, "wifi-scep", "sec", true, false},
		{"short key", "short", token, identity, "wifi-scep", "sec", true, false},
		{"missing identity", challengeKey, token, "", "wifi-scep", "sec", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Accept all identities when enrolled to prove token verification, rather
			// than inventory rejection, blocks an enrolled-device impersonation.
			h := New("sec", tc.key, DeciderFunc(func(string) bool { return tc.enrolled }))
			body := scepBody(t, tc.identity, tc.token, tc.provisioner)
			req := httptest.NewRequest(http.MethodPost, "/scep-challenge", strings.NewReader(body))
			req.Header.Set("X-Smallstep-Signature", sigOf(tc.signingSecret, body))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			var result ResponseShape
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Allow != tc.want {
				t.Fatalf("allow=%v, want %v", result.Allow, tc.want)
			}
		})
	}
	h := New("sec", challengeKey, DeciderFunc(func(string) bool { return true }))
	for _, body := range []string{`{"provisionerName":"wifi-scep","scepChallenge":"` + token + `"}`, `{not json`} {
		req := httptest.NewRequest(http.MethodPost, "/scep-challenge", strings.NewReader(body))
		req.Header.Set("X-Smallstep-Signature", sigOf("sec", body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		var result ResponseShape
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Allow {
			t.Fatal("missing CSR or malformed request must deny")
		}
	}
}

// Exercise the complete SCEP handler -> authorizer -> Fleet HTTP adapter path.
func TestSCEP_BYODEnrollmentIdentity(t *testing.T) {
	const id = "01234567-89ab-cdef-0123-456789abcdef"
	fleetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/latest/fleet/hosts/identifier/"+id {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"host":{"id":42,"uuid":"` + id + `","hardware_serial":"","mdm":{"enrollment_status":"On (personal)"}}}`))
	}))
	defer fleetServer.Close()
	a := authorize.New(fleet.New(fleetServer.URL, "token", time.Second), "")
	h := New("secret", challengeKey, DeciderFunc(func(identity string) bool {
		return a.Decide(context.Background(), identity)
	}))
	for _, tc := range []struct {
		identity, challenge string
		want                bool
	}{
		{id, issueChallenge(t, id, time.Now()), true}, {id, "wrong", false}, {"unknown", issueChallenge(t, "unknown", time.Now()), false},
	} {
		body := scepBody(t, tc.identity, tc.challenge, "wifi-scep")
		req := httptest.NewRequest(http.MethodPost, "/scep-challenge", strings.NewReader(body))
		req.Header.Set("X-Smallstep-Signature", sigOf("secret", body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		var result ResponseShape
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Allow != tc.want {
			t.Fatalf("identity=%s: allow=%v", tc.identity, result.Allow)
		}
	}
	// An anonymous ACME attestation cannot be replaced with an unverified CSR CN.
	body := `{"attestationData":{},"x509CertificateRequest":{"subject":{"commonName":"` + id + `"}}}`
	req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(body))
	req.Header.Set("X-Smallstep-Signature", sigOf("secret", body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var result ResponseShape
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Allow {
		t.Fatal("ACME without an attested identifier must deny")
	}
}
