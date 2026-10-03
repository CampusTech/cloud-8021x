// Package challenge issues short-lived SCEP challenges bound to a certificate
// identity and provisioner. Tokens can be retried for the same identity until
// expiry; they are not single-use credentials.
package challenge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

const (
	MinKeyBytes   = 32
	MaxTTL        = 24 * time.Hour
	maxTokenBytes = 4096
	macDomain     = "cloud-8021x/scep-challenge\x00"
)

type claims struct {
	Identity    string `json:"identity"`
	Provisioner string `json:"provisioner"`
	IssuedAt    int64  `json:"iat"`
	ExpiresAt   int64  `json:"exp"`
}

// NormalizeIdentity matches the legacy certificate CN convention. Opaque
// identities are otherwise case-sensitive and must be supplied consistently.
func NormalizeIdentity(identity string) string {
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(identity), " Campus WiFi"))
}

func validBinding(identity, provisioner string) bool {
	return identity != "" && len(identity) <= 1024 && strings.TrimSpace(provisioner) != "" && len(provisioner) <= 256
}

func signature(key []byte, message string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(macDomain))
	_, _ = mac.Write([]byte(message))
	return mac.Sum(nil)
}

// Issue returns a signed challenge for an identity selected by a trusted issuer.
// The signing key must never be delivered to devices. TTL is in whole seconds.
func Issue(key []byte, identity, provisioner string, now time.Time, ttl time.Duration) (string, error) {
	identity = NormalizeIdentity(identity)
	if len(key) < MinKeyBytes || !validBinding(identity, provisioner) || ttl <= 0 || ttl > MaxTTL || ttl%time.Second != 0 || now.Unix() <= 0 {
		return "", errors.New("invalid SCEP challenge key, identity, provisioner, time, or TTL")
	}
	issued := now.Unix()
	expires := now.Add(ttl).Unix()
	if expires <= issued {
		return "", errors.New("invalid SCEP challenge expiry")
	}
	payload, err := json.Marshal(claims{Identity: identity, Provisioner: provisioner, IssuedAt: issued, ExpiresAt: expires})
	if err != nil {
		return "", err
	}
	message := "v1." + base64.RawURLEncoding.EncodeToString(payload)
	token := message + "." + base64.RawURLEncoding.EncodeToString(signature(key, message))
	if len(token) > maxTokenBytes {
		return "", errors.New("SCEP challenge exceeds maximum length")
	}
	return token, nil
}

// Verify authenticates the token and checks its exact provisioner, normalized
// CSR identity, lifetime, and validity at now. Legacy shared passwords fail closed.
func Verify(key []byte, token, identity, provisioner string, now time.Time) bool {
	identity = NormalizeIdentity(identity)
	if len(key) < MinKeyBytes || len(token) > maxTokenBytes || !validBinding(identity, provisioner) {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return false
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, signature(key, parts[0]+"."+parts[1])) {
		return false
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return false
	}
	var c claims
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&c) != nil {
		return false
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return false
	}
	if c.Identity != identity || c.Provisioner != provisioner || c.IssuedAt <= 0 || c.ExpiresAt <= c.IssuedAt || c.ExpiresAt-c.IssuedAt > int64(MaxTTL/time.Second) {
		return false
	}
	return c.IssuedAt <= now.Unix() && now.Unix() < c.ExpiresAt
}
