package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
