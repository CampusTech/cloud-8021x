package main

import (
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/webhook/challenge"
)

func TestBrokerReplyPreservesGenuineOpaqueChallengeWithoutAuthorityKey(t *testing.T) {
	now := time.Now().UTC()
	key := []byte(strings.Repeat("test-only-key", 4))
	token, e := challenge.IssueInventory(key, "wifi-scep", now)
	if e != nil {
		t.Fatal(e)
	}
	actual, e := brokerChallengeReply(200, "text/plain; charset=utf-8", []byte(token))
	if e != nil {
		t.Fatal(e)
	}
	if actual != token || !challenge.VerifyInventory(key, actual, "wifi-scep", now) {
		t.Fatal("opaque genuine broker bytes reconstructed/changed")
	}
	for _, bad := range []struct {
		status int
		media  string
		body   []byte
	}{
		{401, "text/plain", []byte("unauthorized")},
		{200, "application/json", []byte(`{"challenge":"opaque"}`)},
		{200, "text/html", []byte("<b>opaque</b>")},
		{201, "text/plain", []byte(token)},
		{200, "text/plain", nil},
		{200, "text/plain", []byte(token + "\n")},
		{200, "text/plain", []byte(token + " ")},
		{200, "text/plain", []byte("\x00")},
		{200, "text/plain", []byte(strings.Repeat("a", 4097))},
	} {
		if _, e := brokerChallengeReply(bad.status, bad.media, bad.body); e == nil {
			t.Fatal("invalid/oversized broker reply accepted")
		}
	}
}
