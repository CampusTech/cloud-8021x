package signature

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func sign(secret, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

func TestVerify_GoodSignature(t *testing.T) {
	secret := []byte("s3cr3t")
	body := []byte(`{"hello":"world"}`)
	if !Verify(secret, body, sign(secret, body)) {
		t.Fatal("expected valid signature to verify")
	}
}

func TestVerify_BadSignature(t *testing.T) {
	secret := []byte("s3cr3t")
	body := []byte(`{"hello":"world"}`)
	if Verify(secret, body, sign([]byte("wrong"), body)) {
		t.Fatal("expected wrong-key signature to fail")
	}
	if Verify(secret, body, "not-hex") {
		t.Fatal("expected malformed signature to fail")
	}
	if Verify(secret, body, "") {
		t.Fatal("expected empty signature to fail")
	}
}
