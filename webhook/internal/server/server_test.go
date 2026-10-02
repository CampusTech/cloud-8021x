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

func TestSCEPChallengeHandler(t *testing.T) {
	secret := "sec"
	challenge := "shared-challenge"

	h := New(secret, challenge, DeciderFunc(func(serial string) bool { return serial == "FRAGAACPA74412000D" }))
	srv := httptest.NewServer(h)
	defer srv.Close()

	post := func(b, sig string) ResponseShape {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/scep-challenge", strings.NewReader(b))
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

	// Valid: correct sig + correct challenge + enrolled (macOS bare-serial) CN.
	bare := `{"scepChallenge":"shared-challenge","x509CertificateRequest":{"subject":{"commonName":"FRAGAACPA74412000D"}}}`
	if rs := post(bare, sigOf(secret, bare)); !rs.Allow {
		t.Fatal("expected allow for good sig + correct challenge + enrolled serial")
	}

	// Windows CN carries a " Campus WiFi" suffix that must be stripped.
	suffixed := `{"scepChallenge":"shared-challenge","x509CertificateRequest":{"subject":{"commonName":"FRAGAACPA74412000D Campus WiFi"}}}`
	if rs := post(suffixed, sigOf(secret, suffixed)); !rs.Allow {
		t.Fatal("expected allow: \" Campus WiFi\" suffix must be stripped to the serial")
	}

	// Wrong challenge value must deny even with a valid signature.
	wrongChal := `{"scepChallenge":"nope","x509CertificateRequest":{"subject":{"commonName":"FRAGAACPA74412000D"}}}`
	if rs := post(wrongChal, sigOf(secret, wrongChal)); rs.Allow {
		t.Fatal("wrong challenge must deny")
	}

	// Bad signature must deny.
	if rs := post(bare, sigOf("wrong", bare)); rs.Allow {
		t.Fatal("bad signature must deny")
	}

	// Missing CSR must deny.
	noCSR := `{"scepChallenge":"shared-challenge"}`
	if rs := post(noCSR, sigOf(secret, noCSR)); rs.Allow {
		t.Fatal("missing CSR must deny")
	}

	// Unknown serial must deny.
	unk := `{"scepChallenge":"shared-challenge","x509CertificateRequest":{"subject":{"commonName":"NOPE"}}}`
	if rs := post(unk, sigOf(secret, unk)); rs.Allow {
		t.Fatal("unknown serial must deny")
	}
}

func TestSCEPChallengeHandler_NoChallengeConfigured(t *testing.T) {
	secret := "sec"

	// Empty configured challenge: a SCEP request is a misconfiguration -> deny.
	h := New(secret, "", DeciderFunc(func(serial string) bool { return true }))
	srv := httptest.NewServer(h)
	defer srv.Close()

	body := `{"scepChallenge":"","x509CertificateRequest":{"subject":{"commonName":"FRAGAACPA74412000D"}}}`
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/scep-challenge", strings.NewReader(body))
	req.Header.Set("X-Smallstep-Signature", sigOf(secret, body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var rs ResponseShape
	_ = json.NewDecoder(resp.Body).Decode(&rs)
	if rs.Allow {
		t.Fatal("empty configured challenge must deny (fail-closed)")
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
	h := New("secret", "challenge", DeciderFunc(func(identity string) bool {
		return a.Decide(context.Background(), identity)
	}))
	for _, tc := range []struct {
		identity, challenge string
		want                bool
	}{
		{id, "challenge", true}, {id, "wrong", false}, {"unknown", "challenge", false},
	} {
		body := `{"scepChallenge":"` + tc.challenge + `","x509CertificateRequest":{"subject":{"commonName":"` + tc.identity + `"}}}`
		req := httptest.NewRequest(http.MethodPost, "/scep-challenge", strings.NewReader(body))
		req.Header.Set("X-Smallstep-Signature", sigOf("secret", body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		var result ResponseShape
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Allow != tc.want {
			t.Fatalf("identity=%s challenge=%s: allow=%v", tc.identity, tc.challenge, result.Allow)
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
