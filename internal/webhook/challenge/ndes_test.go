package challenge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNDESInventoryScopeAndLifetime(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	now := time.Unix(1800000000, 0)
	for _, tc := range []struct {
		name, version, domain, provisioner string
		ttl, timeOffset                    time.Duration
		want                               bool
	}{
		{"NDES cached", "v3", "cloud-8021x/scep-ndes-inventory-challenge/v3\x00", "wifi-scep", time.Hour, 57 * time.Minute, true},
		{"NDES retry", "v3", "cloud-8021x/scep-ndes-inventory-challenge/v3\x00", "wifi-scep", time.Hour, 59 * time.Minute, true},
		{"NDES expiry", "v3", "cloud-8021x/scep-ndes-inventory-challenge/v3\x00", "wifi-scep", time.Hour, time.Hour, false},
		{"NDES future", "v3", "cloud-8021x/scep-ndes-inventory-challenge/v3\x00", "wifi-scep", time.Hour, -time.Second, false},
		{"NDES excessive lifetime", "v3", "cloud-8021x/scep-ndes-inventory-challenge/v3\x00", "wifi-scep", time.Hour + time.Second, 0, false},
		{"NDES wrong provisioner", "v3", "cloud-8021x/scep-ndes-inventory-challenge/v3\x00", "other", time.Hour, 0, false},
		{"v2 excessive lifetime", "v2", inventoryDomain, "wifi-scep", time.Hour, 0, false},
		{"v2 domain with v3 prefix", "v3", inventoryDomain, "wifi-scep", time.Hour, 0, false},
		{"v3 domain with v2 prefix", "v2", "cloud-8021x/scep-ndes-inventory-challenge/v3\x00", "wifi-scep", 15 * time.Minute, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := json.Marshal(inventoryClaims{Provisioner: tc.provisioner, Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), IssuedAt: now.Unix(), ExpiresAt: now.Add(tc.ttl).Unix()})
			if err != nil {
				t.Fatal(err)
			}
			encoding := base64.RawURLEncoding
			if tc.version == "v3" {
				encoding = base64.RawStdEncoding
			}
			message := tc.version + "." + encoding.EncodeToString(payload)
			mac := hmac.New(sha256.New, key)
			_, _ = mac.Write([]byte(tc.domain + message))
			token := message + "." + encoding.EncodeToString(mac.Sum(nil))
			if got := VerifyInventory(key, token, "wifi-scep", now.Add(tc.timeOffset)); got != tc.want {
				t.Fatalf("accepted=%v want=%v", got, tc.want)
			}
			if VerifyInventory(key, token+"x", "wifi-scep", now) {
				t.Fatal("tampered token accepted")
			}
			if VerifyInventory([]byte(strings.Repeat("x", 32)), token, "wifi-scep", now) {
				t.Fatal("wrong key accepted")
			}
		})
	}
}
