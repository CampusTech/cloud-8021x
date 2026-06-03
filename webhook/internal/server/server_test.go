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

	h := New(secret, DeciderFunc(func(serial string) bool { return serial == "S1" }))
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
		defer resp.Body.Close()
		var rs ResponseShape
		json.NewDecoder(resp.Body).Decode(&rs)
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
