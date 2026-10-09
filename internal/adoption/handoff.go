// Package adoption defines the closed authorization-only cross-deployment
// handoff. Accounting state has no representation in this protocol.
package adoption

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/migration"
)

const MaxBytes = 40 << 20
const MaxCaptureAge = 10 * time.Minute
const signatureDomain = "cloud8021x-parallel-authorization-v1\x00"

type Binding struct {
	Transition, ManifestSHA256, ConfigSHA256, ReleaseSHA256      string
	SourceDeployment, SourceInstance, Deployment, Instance, Role string
	CollectionEpoch                                              time.Time
}
type NativeIdentity struct {
	WebhookCertificate, WebhookKey, ECConfig, RSAConfig, ECTemplate, RSATemplate []byte
}
type Authorization struct {
	Native                                                    *NativeIdentity `json:",omitempty"`
	Binding                                                   Binding
	CapturedAt                                                time.Time
	FenceSHA256, SourceConfigSHA256, ClassSHA256, TrustSHA256 string
	FingerprintEnforced                                       bool
	Policy, Certificates                                      json.RawMessage
}
type Envelope struct {
	Version   int
	Document  json.RawMessage
	Signature []byte
}

func Digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func validate(a Authorization) error {
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for _, s := range []string{a.Binding.Transition, a.Binding.ManifestSHA256, a.Binding.ConfigSHA256, a.Binding.ReleaseSHA256, a.FenceSHA256, a.SourceConfigSHA256, a.ClassSHA256, a.TrustSHA256} {
		if !hex64.MatchString(s) {
			return errors.New("incomplete handoff digest binding")
		}
	}
	if a.Binding.SourceDeployment == "" || a.Binding.Deployment == "" || a.Binding.SourceDeployment == a.Binding.Deployment || a.Binding.SourceInstance == a.Binding.Instance || (a.Binding.Role != "radius-primary" && a.Binding.Role != "radius-secondary") || a.Binding.CollectionEpoch.IsZero() || a.CapturedAt.IsZero() {
		return errors.New("incomplete source and destination binding")
	}
	snapshot, err := domain.DecodeSnapshot(bytes.NewReader(a.Policy))
	if err != nil || snapshot.Version != 2 {
		return errors.New("original fingerprint authorization required")
	}
	if _, err = migration.DecodeCertificates(a.Certificates); err != nil {
		return err
	}
	return nil
}
func Sign(a Authorization, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("protected source signing key required")
	}
	if err := validate(a); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	signature := ed25519.Sign(key, append([]byte(signatureDomain), raw...))
	result, err := json.Marshal(Envelope{Version: 1, Document: raw, Signature: signature})
	if len(result) > MaxBytes {
		return nil, errors.New("handoff exceeds bound")
	}
	return result, err
}
func Verify(raw []byte, key ed25519.PublicKey, expected Binding, now time.Time) (Authorization, error) {
	var envelope Envelope
	if len(raw) > MaxBytes || len(key) != ed25519.PublicKeySize || domain.DecodeJSONStrict(raw, &envelope) != nil || envelope.Version != 1 || !ed25519.Verify(key, append([]byte(signatureDomain), envelope.Document...), envelope.Signature) {
		return Authorization{}, errors.New("authenticated original source handoff required")
	}
	var a Authorization
	if domain.DecodeJSONStrict(envelope.Document, &a) != nil {
		return a, errors.New("invalid typed authorization handoff")
	}
	// JSON preserves the epoch instant, not time.Location pointer identity.
	actual, wanted := a.Binding, expected
	actual.CollectionEpoch = actual.CollectionEpoch.UTC()
	wanted.CollectionEpoch = wanted.CollectionEpoch.UTC()
	if actual != wanted {
		return a, errors.New("source handoff destination/config/release differs")
	}
	if a.CapturedAt.After(now) || now.Sub(a.CapturedAt) > MaxCaptureAge {
		return a, errors.New("fresh source scheduler quiescence proof required")
	}
	return a, validate(a)
}
