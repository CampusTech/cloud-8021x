package challenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

// InventoryTTL bounds reusable issuance credentials; inventory, not CSR identity,
// determines network access by the exact certificate fingerprint after issuance.
const InventoryTTL = 15 * time.Minute
const inventoryDomain = "cloud-8021x/scep-inventory-challenge/v2\x00"

type inventoryClaims struct {
	Provisioner string `json:"provisioner"`
	Nonce       string `json:"nonce"`
	IssuedAt    int64  `json:"iat"`
	ExpiresAt   int64  `json:"exp"`
}

func inventorySignature(key []byte, message string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(inventoryDomain))
	_, _ = mac.Write([]byte(message))
	return mac.Sum(nil)
}

// IssueInventory authorizes neutral certificate issuance, not a device identity.
// Tokens intentionally permit retries during their short lifetime.
func IssueInventory(key []byte, provisioner string, now time.Time) (string, error) {
	if len(key) < MinKeyBytes || !validBinding("inventory", provisioner) || now.Unix() <= 0 {
		return "", errors.New("invalid inventory challenge signing configuration")
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	payload, err := json.Marshal(inventoryClaims{Provisioner: provisioner, Nonce: base64.RawURLEncoding.EncodeToString(nonce), IssuedAt: now.Unix(), ExpiresAt: now.Add(InventoryTTL).Unix()})
	if err != nil {
		return "", err
	}
	message := "v2." + base64.RawURLEncoding.EncodeToString(payload)
	return message + "." + base64.RawURLEncoding.EncodeToString(inventorySignature(key, message)), nil
}

// VerifyInventory is usable only when certificate inventory authorization is
// enabled. It never establishes a device identity from the request or CSR.
func VerifyInventory(key []byte, token, provisioner string, now time.Time) bool {
	if len(key) < MinKeyBytes || len(token) > maxTokenBytes || !validBinding("inventory", provisioner) {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "v2" {
		return false
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, inventorySignature(key, parts[0]+"."+parts[1])) {
		return false
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return false
	}
	var c inventoryClaims
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&c) != nil {
		return false
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return false
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(c.Nonce)
	if err != nil || len(nonce) != 32 || c.Provisioner != provisioner || c.IssuedAt <= 0 || c.ExpiresAt <= c.IssuedAt || c.ExpiresAt-c.IssuedAt > int64(InventoryTTL/time.Second) {
		return false
	}
	return c.IssuedAt <= now.Unix() && now.Unix() < c.ExpiresAt
}
