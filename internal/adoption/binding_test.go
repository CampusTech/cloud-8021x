package adoption

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"
)

func TestExpectedBindingPreventsSignedHandoffRetargeting(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	primary := config.Defaults()
	primary.InstanceID = "radius-primary"
	primary.Database.Name = "cloud8021x_green"
	primary.StateTransition = strings.Repeat("a", 64)
	primary.Deployment = config.Deployment{Mode: "parallel", ID: "green", Instance: "green-primary", SourceID: "blue", SourcePrimary: "blue-primary", SourceSecondary: "blue-secondary", CollectionEpoch: now}
	primary.Bootstrap.LocalAddress, primary.Bootstrap.PeerAddress = "10.0.0.1", "10.0.0.2"
	secondary := primary
	secondary.InstanceID, secondary.Deployment.Instance = "radius-secondary", "green-secondary"
	secondary.Bootstrap.LocalAddress, secondary.Bootstrap.PeerAddress = primary.Bootstrap.PeerAddress, primary.Bootstrap.LocalAddress
	release := strings.Repeat("d", 64)
	first, err := ExpectedBinding(primary, release)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ExpectedBinding(secondary, release)
	if err != nil {
		t.Fatal(err)
	}
	if first.ManifestSHA256 != second.ManifestSHA256 || first.ConfigSHA256 == second.ConfigSHA256 {
		t.Fatal("pair must share its manifest while retaining distinct physical configuration proofs")
	}
	for _, cfg := range []config.Config{primary, secondary} {
		t.Run(cfg.InstanceID, func(t *testing.T) {
			binding, err := ExpectedBinding(cfg, release)
			if err != nil {
				t.Fatal(err)
			}
			source := "blue-primary"
			if cfg.InstanceID == "radius-secondary" {
				source = "blue-secondary"
			}
			if binding.SourceInstance != source || binding.Role != cfg.InstanceID || binding.Instance != cfg.Deployment.Instance {
				t.Fatal("logical role must select the matching original and destination physical hosts")
			}
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			doc := Authorization{Binding: binding, CapturedAt: now, FenceSHA256: strings.Repeat("e", 64), SourceConfigSHA256: strings.Repeat("f", 64), ClassSHA256: strings.Repeat("1", 64), TrustSHA256: strings.Repeat("7", 64), Policy: json.RawMessage(`{"version":2,"updated_at":1800000000,"identities":{},"certificates":{},"hardware_serials":{}}`), Certificates: json.RawMessage(`{"version":1,"source":"https://fleet.example.test","trust":null,"hosts":{},"commands":[]}`)}
			raw, err := Sign(doc, key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = Verify(raw, pub, binding, now); err != nil {
				t.Fatal(err)
			}
			for name, mutate := range map[string]func(*config.Config, *string){
				"opposite physical role": func(c *config.Config, _ *string) {
					if c.InstanceID == "radius-primary" {
						*c = secondary
					} else {
						*c = primary
					}
				},
				"node config": func(c *config.Config, _ *string) { c.Hostname = "changed.example.test" },
				"release":     func(_ *config.Config, r *string) { *r = strings.Repeat("9", 64) },
				"original source": func(c *config.Config, _ *string) {
					c.Deployment.SourcePrimary = "other-primary"
					c.Deployment.SourceSecondary = "other-secondary"
				},
				"source deployment": func(c *config.Config, _ *string) { c.Deployment.SourceID = "other-blue" },
				"destination deployment": func(c *config.Config, _ *string) {
					c.Deployment.ID = "red"
					c.Deployment.Instance = "red" + strings.TrimPrefix(c.InstanceID, "radius")
					c.Database.Name = "cloud8021x_red"
				},
				"transition": func(c *config.Config, _ *string) { c.StateTransition = strings.Repeat("b", 64) },
				"epoch":      func(c *config.Config, _ *string) { c.Deployment.CollectionEpoch = now.Add(time.Second) },
			} {
				t.Run(name, func(t *testing.T) {
					changed, changedRelease := cfg, release
					mutate(&changed, &changedRelease)
					expected, err := ExpectedBinding(changed, changedRelease)
					if err != nil {
						t.Fatal(err)
					}
					if _, err = Verify(raw, pub, expected, now); err == nil {
						t.Fatal("signed handoff accepted for a different expected authority")
					}
				})
			}
		})
	}
	invalid := primary
	invalid.InstanceID = "arbitrary-role"
	if _, err := ExpectedBinding(invalid, release); err == nil {
		t.Fatal("invalid role accepted")
	}
}
