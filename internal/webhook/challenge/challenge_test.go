package challenge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestIdentityAndProvisionerBinding(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	now := time.Unix(1800000000, 0)
	token, err := Issue(key, " byod-device Campus WiFi ", "wifi-scep", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, identity, provisioner string
		key                         []byte
		now                         time.Time
		want                        bool
	}{
		{"valid", "byod-device", "wifi-scep", key, now, true},
		{"legacy CN", "byod-device Campus WiFi", "wifi-scep", key, now, true},
		{"same identity retry", "byod-device", "wifi-scep", key, now.Add(time.Minute), true},
		{"different device", "staff-device", "wifi-scep", key, now, false},
		{"different provisioner", "byod-device", "other-scep", key, now, false},
		{"missing provisioner", "byod-device", "", key, now, false},
		{"missing identity", "", "wifi-scep", key, now, false},
		{"future token", "byod-device", "wifi-scep", key, now.Add(-time.Second), false},
		{"expired", "byod-device", "wifi-scep", key, now.Add(time.Hour), false},
		{"wrong key", "byod-device", "wifi-scep", []byte(strings.Repeat("x", 32)), now, false},
		{"missing key", "byod-device", "wifi-scep", nil, now, false},
		{"short key", "byod-device", "wifi-scep", key[:31], now, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Verify(tc.key, token, tc.identity, tc.provisioner, tc.now); got != tc.want {
				t.Fatalf("Verify = %v, want %v", got, tc.want)
			}
		})
	}
	parts := strings.Split(token, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(strings.ReplaceAll(string(payload), "byod-device", "staff-device")))
	if Verify(key, strings.Join(parts, "."), "staff-device", "wifi-scep", now) {
		t.Fatal("changed identity accepted without new signature")
	}
	for _, malformed := range []string{"", string(key), "v1.bad.bad", token + ".extra", "v2" + token[2:], strings.Repeat("x", 4097)} {
		if Verify(key, malformed, "byod-device", "wifi-scep", now) {
			t.Fatal("malformed or shared password accepted")
		}
	}
}

func TestIssueRejectsInvalidConfiguration(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	now := time.Unix(1800000000, 0)
	for _, tc := range []struct {
		name, identity, provisioner string
		key                         []byte
		ttl                         time.Duration
	}{
		{"missing key", "device", "wifi", nil, time.Hour},
		{"short key", "device", "wifi", key[:31], time.Hour},
		{"missing identity", "  ", "wifi", key, time.Hour},
		{"missing provisioner", "device", "", key, time.Hour},
		{"whitespace provisioner", "device", " ", key, time.Hour},
		{"zero ttl", "device", "wifi", key, 0},
		{"negative ttl", "device", "wifi", key, -time.Second},
		{"fractional ttl", "device", "wifi", key, time.Millisecond},
		{"long ttl", "device", "wifi", key, 24*time.Hour + time.Second},
		{"oversize identity", strings.Repeat("x", 1025), "wifi", key, time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Issue(tc.key, tc.identity, tc.provisioner, now, tc.ttl); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

// Verify must validate temporal claims even when authenticated by the signing key.
func TestVerifyRejectsInvalidSignedClaims(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	now := time.Unix(1800000000, 0)
	for _, payload := range []string{
		`{"identity":"device","provisioner":"wifi","iat":1800000000,"exp":1800086401}`,
		`{"identity":"device","provisioner":"wifi","iat":1800000000,"exp":1800000000}`,
		`{"identity":"device","provisioner":"wifi","iat":1800000001,"exp":1800001000}`,
		`{"identity":"device","provisioner":"wifi","exp":1800001000}`,
		`{"identity":"device","provisioner":"wifi","iat":-9223372036854775808,"exp":1800001000}`,
		`{"identity":"device","provisioner":"wifi","iat":1800000000,"exp":1800001000,"extra":true}`,
		`{broken`,
	} {
		message := "v1." + base64.RawURLEncoding.EncodeToString([]byte(payload))
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte("cloud-8021x/scep-challenge\x00" + message))
		token := message + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if Verify(key, token, "device", "wifi", now) {
			t.Fatalf("invalid claims accepted: %s", payload)
		}
	}
}
