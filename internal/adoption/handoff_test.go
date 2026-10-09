package adoption

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSignedAuthorizationHandoffRejectsWrongAuthorityAndReplay(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1800000000, 0)
	b := Binding{Transition: strings.Repeat("a", 64), ManifestSHA256: strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64), ReleaseSHA256: strings.Repeat("d", 64), SourceDeployment: "blue", SourceInstance: "radius-primary", Deployment: "green", Instance: "green-primary", Role: "radius-primary", CollectionEpoch: now}
	doc := Authorization{Binding: b, CapturedAt: now, FenceSHA256: strings.Repeat("e", 64), SourceConfigSHA256: strings.Repeat("f", 64), ClassSHA256: strings.Repeat("1", 64), TrustSHA256: strings.Repeat("7", 64), Policy: json.RawMessage(`{"version":2,"updated_at":1800000000,"identities":{},"certificates":{},"hardware_serials":{}}`), Certificates: json.RawMessage(`{"version":1,"source":"https://fleet.example.test","trust":null,"hosts":{},"commands":[]}`), FingerprintEnforced: true}
	raw, err := Sign(doc, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(raw, pub, b, now); err != nil {
		t.Fatal(err)
	}
	alias := b
	alias.CollectionEpoch = b.CollectionEpoch.In(time.FixedZone("UTC alias", 0))
	if _, err = Verify(raw, pub, alias, now); err != nil {
		t.Fatal("same signed epoch instant differs by location identity", err)
	}
	alias.CollectionEpoch = alias.CollectionEpoch.Add(time.Second)
	if _, err = Verify(raw, pub, alias, now); err == nil {
		t.Fatal("different epoch instant accepted")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err = Verify(raw, other, b, now); err == nil {
		t.Fatal("untrusted source key")
	}
	wrong := b
	wrong.Deployment = "red"
	if _, err = Verify(raw, pub, wrong, now); err == nil {
		t.Fatal("foreign destination")
	}
	if _, err = Verify(raw, pub, b, now.Add(11*time.Minute)); err == nil {
		t.Fatal("stale source capture")
	}
	raw[len(raw)/2] ^= 1
	if _, err = Verify(raw, pub, b, now); err == nil {
		t.Fatal("tampered source")
	}
}
