package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/config"
)

func TestTransferVerifiesAuthorityAndFreshnessBeforeWriting(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	cfg := config.Defaults()
	cfg.InstanceID = "radius-primary"
	cfg.Database.Name = "cloud8021x_task11_green"
	cfg.StateTransition = strings.Repeat("a", 64)
	cfg.Deployment = config.Deployment{Mode: "parallel", ID: "task11-green", Instance: "task11-green-primary", SourceID: "task11-blue", SourcePrimary: "task11-blue-primary", SourceSecondary: "task11-blue-secondary", CollectionEpoch: now}
	var keys []ed25519.PrivateKey
	var pins []string
	for range 4 {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
		pins = append(pins, hex.EncodeToString(pub))
	}
	cfg.Deployment.SourcePrimaryKey = pins[0]
	cfg.Deployment.SourceSecondaryKey = pins[1]
	cfg.Deployment.DestinationPrimaryKey = pins[2]
	cfg.Deployment.DestinationSecondaryKey = pins[3]
	release := strings.Repeat("b", 64)
	binding, err := adoption.ExpectedBinding(cfg, release)
	if err != nil {
		t.Fatal(err)
	}
	a := adoption.Authorization{Binding: binding, CapturedAt: now, FenceSHA256: release, SourceConfigSHA256: release, ClassSHA256: release, TrustSHA256: release, Policy: json.RawMessage(`{"version":2,"updated_at":1800000000,"identities":{},"certificates":{},"hardware_serials":{}}`), Certificates: json.RawMessage(`{"version":1,"source":"https://fleet.example.test","trust":null,"hosts":{},"commands":[]}`)}
	raw, err := adoption.Sign(a, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyReceipt("parallel", "radius-primary", raw, cfg, release, now); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, kind, role, release string
		at                        time.Time
		raw                       []byte
	}{{"wrong-role", "parallel", "radius-secondary", release, now, raw}, {"release", "parallel", "radius-primary", strings.Repeat("c", 64), now, raw}, {"stale", "parallel", "radius-primary", release, now.Add(11 * time.Minute), raw}, {"future", "parallel", "radius-primary", release, now.Add(-time.Second), raw}, {"forgery", "parallel", "radius-primary", release, now, append([]byte("!"), raw...)}} {
		t.Run(tc.name, func(t *testing.T) {
			if verifyReceipt(tc.kind, tc.role, tc.raw, cfg, tc.release, tc.at) == nil {
				t.Fatal("unauthenticated transfer accepted")
			}
		})
	}
	r := adoption.Rollback{ManifestSHA256: binding.ManifestSHA256, ReleaseSHA256: release, Transition: cfg.StateTransition, Deployment: cfg.Deployment.ID, SourceDeployment: cfg.Deployment.SourceID, Role: "radius-primary", Instance: "task11-green-primary", FenceSHA256: release, ObservedAt: now, CommandsReconciled: true}
	proof, err := adoption.SignRollback(r, keys[2])
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyReceipt("rollback", "radius-primary", proof, cfg, release, now); err != nil {
		t.Fatal(err)
	}
	forged, err := adoption.SignRollback(r, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if verifyReceipt("rollback", "radius-primary", forged, cfg, release, now) == nil {
		t.Fatal("source key accepted as destination proof")
	}
}
