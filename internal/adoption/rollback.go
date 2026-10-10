package adoption

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

const rollbackDomain = "cloud8021x-parallel-rollback-v1\x00"

type Rollback struct {
	ManifestSHA256, ReleaseSHA256, Transition, Deployment, SourceDeployment, Role, Instance, FenceSHA256 string
	ObservedAt                                                                                           time.Time
	CommandsReconciled                                                                                   bool
}

func validRollback(r Rollback) bool {
	digest := regexp.MustCompile(`^[0-9a-f]{64}$`)
	suffix := map[string]string{"radius-primary": "-primary", "radius-secondary": "-secondary"}[r.Role]
	return digest.MatchString(r.ReleaseSHA256) && digest.MatchString(r.ManifestSHA256) && digest.MatchString(r.Transition) && digest.MatchString(r.FenceSHA256) && r.CommandsReconciled && !r.ObservedAt.IsZero() && suffix != "" && r.Deployment != "" && r.SourceDeployment != "" && r.Deployment != r.SourceDeployment && r.Instance == r.Deployment+suffix
}
func SignRollback(r Rollback, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize || !validRollback(r) {
		return nil, errors.New("complete physical rollback evidence required")
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Envelope{Version: 1, Document: raw, Signature: ed25519.Sign(key, append([]byte(rollbackDomain), raw...))})
}
func VerifyRollback(raw []byte, key ed25519.PublicKey, manifest, release, transition, deployment, source, role string, now time.Time) (Rollback, error) {
	var e Envelope
	var r Rollback
	if len(raw) > 64<<10 || len(key) != ed25519.PublicKeySize || domain.DecodeJSONStrict(raw, &e) != nil || e.Version != 1 || !ed25519.Verify(key, append([]byte(rollbackDomain), e.Document...), e.Signature) || domain.DecodeJSONStrict(e.Document, &r) != nil {
		return r, errors.New("authenticated green rollback receipt required")
	}
	if !validRollback(r) || r.ManifestSHA256 != manifest || r.ReleaseSHA256 != release || r.Transition != transition || r.Deployment != deployment || r.SourceDeployment != source || r.Role != role || r.ObservedAt.After(now) || now.Sub(r.ObservedAt) > MaxCaptureAge {
		return r, errors.New("green rollback proof is incomplete or stale")
	}
	return r, nil
}
