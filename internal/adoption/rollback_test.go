package adoption

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestRollbackReceiptRefusesWrongKeyPendingAndReplay(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	proof := Rollback{ReleaseSHA256: strings.Repeat("d", 64), ManifestSHA256: strings.Repeat("a", 64), Transition: strings.Repeat("b", 64), Deployment: "green", SourceDeployment: "blue", Role: "radius-primary", Instance: "green-primary", FenceSHA256: strings.Repeat("c", 64), ObservedAt: now, CommandsReconciled: true}
	raw, err := SignRollback(proof, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyRollback(raw, pub, proof.ManifestSHA256, proof.ReleaseSHA256, proof.Transition, "green", "blue", "radius-primary", now); err != nil {
		t.Fatal(err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	for _, tc := range []struct {
		key  ed25519.PublicKey
		role string
		at   time.Time
	}{{other, "radius-primary", now}, {pub, "radius-secondary", now}, {pub, "radius-primary", now.Add(11 * time.Minute)}} {
		if _, err = VerifyRollback(raw, tc.key, proof.ManifestSHA256, proof.ReleaseSHA256, proof.Transition, "green", "blue", tc.role, tc.at); err == nil {
			t.Fatal("untrusted rollback proof accepted")
		}
	}
	proof.CommandsReconciled = false
	if _, err = SignRollback(proof, key); err == nil {
		t.Fatal("unresolved command state signed as safe")
	}
}
