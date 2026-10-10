package challenge

import (
	"strings"
	"testing"
	"time"
)

func TestInventoryChallengeScopeAndLifetime(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	now := time.Unix(1800000000, 0)
	token, err := IssueInventory(key, "wifi-scep", now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := IssueInventory(key, "wifi-scep", now)
	if err != nil {
		t.Fatal(err)
	}
	if token == other {
		t.Fatal("fresh challenges must have independent random nonces")
	}
	for _, tc := range []struct {
		name, provisioner string
		at                time.Time
		want              bool
	}{
		{"initial", "wifi-scep", now, true}, {"retry", "wifi-scep", now.Add(14 * time.Minute), true},
		{"expired", "wifi-scep", now.Add(15 * time.Minute), false}, {"future", "wifi-scep", now.Add(-time.Second), false},
		{"wrong provisioner", "other", now, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := VerifyInventory(key, token, tc.provisioner, tc.at); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
	if Verify(key, token, "staff", "wifi-scep", now) {
		t.Fatal("inventory token accepted by legacy verifier")
	}
	legacy, _ := Issue(key, "staff", "wifi-scep", now, time.Hour)
	if VerifyInventory(key, legacy, "wifi-scep", now) {
		t.Fatal("legacy token accepted as inventory token")
	}
	if VerifyInventory([]byte(strings.Repeat("x", 32)), token, "wifi-scep", now) {
		t.Fatal("wrong signing key accepted")
	}
	if VerifyInventory(key, token+"x", "wifi-scep", now) {
		t.Fatal("tampering accepted")
	}
	for _, provisioner := range []string{"", " ", strings.Repeat("x", 257)} {
		if _, err := IssueInventory(key, provisioner, now); err == nil {
			t.Fatal("invalid provisioner accepted")
		}
	}
	if _, err := IssueInventory([]byte("short"), "wifi-scep", now); err == nil {
		t.Fatal("weak signing key accepted")
	}
}
