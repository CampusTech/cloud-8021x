package fleet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/migration"
)

type inheritedCollectionRepository interface {
	InheritedCollection(context.Context, string) ([]byte, error)
}

// Inherited observations keep their original provenance and times. Current
// authenticated Fleet detail must still prove the complete original binding.
func (c *Collector) inheritedObservation(ctx context.Context, current host, binding reservation, age time.Duration) (*domain.CertificateObservation, time.Time, error) {
	repository, ok := c.Repository.(inheritedCollectionRepository)
	if !ok {
		return nil, time.Time{}, nil
	}
	raw, err := repository.InheritedCollection(ctx, binding.LegacyScope)
	if err != nil || len(raw) == 0 {
		return nil, time.Time{}, err
	}
	state, err := migration.DecodeCertificates(raw)
	if err != nil || len(state.Hosts) != 1 || len(state.Commands) != 0 {
		return nil, time.Time{}, errors.New("invalid inherited Fleet observation")
	}
	original, ok := state.Hosts[current.UUID]
	if !ok || state.Source != c.Maintainer.base || state.Trust == nil || *state.Trust != c.Trust.digest || original.Platform != current.Platform {
		return nil, time.Time{}, nil
	}
	var id uint64
	var enrolled float64
	var fleetEnrollment *string
	enrollment := current.MDMEnrolledAt
	if current.Platform == "windows" {
		enrollment = current.EnrolledAt
	}
	at, err := time.Parse(time.RFC3339Nano, enrollment)
	// The source Python parser truncates enrollment to microseconds. Keep its
	// original JSON intact while comparing that exact numeric representation.
	if err != nil || json.Unmarshal(original.Binding[0], &id) != nil || id != uint64(current.ID) || json.Unmarshal(original.Binding[1], &enrolled) != nil || enrolled <= 0 || enrolled != float64(domain.Unix(at.Truncate(time.Microsecond))) || json.Unmarshal(original.Binding[2], &fleetEnrollment) != nil || (fleetEnrollment == nil && current.EnrolledAt != "") || (fleetEnrollment != nil && (*fleetEnrollment == "" || *fleetEnrollment != current.EnrolledAt)) {
		return nil, time.Time{}, nil
	}
	if current.Platform == "windows" {
		var originalScript string
		script := sha256.Sum256([]byte(windowsScript))
		if json.Unmarshal(original.Binding[3], &originalScript) != nil || originalScript != hex.EncodeToString(script[:]) {
			return nil, time.Time{}, nil
		}
	}
	now := c.now()
	last, _ := migration.ReceiptTime([]byte(original.LastAttempt))
	if last.After(now) || last.Before(at.Truncate(time.Microsecond)) {
		last = time.Time{}
	}
	observation := original.Observation
	if observation == nil || !observation.TrustVerified {
		return nil, last, nil
	}
	timestamp, err := observation.ObservedAt.Float64()
	observed := domain.Timestamp(timestamp)
	if err != nil || timestamp < enrolled || !domain.Fresh(observed, now, age) {
		return nil, last, nil
	}
	out := &domain.CertificateObservation{DeviceID: domain.DeviceID("fleet:" + itoa(current.ID)), Fingerprints: []string{}, ObservedAt: observed, TrustVerified: true, Provenance: "inherited-handoff:" + binding.LegacyScope, ExpiresAt: map[string]domain.Timestamp{}}
	for _, fingerprint := range observation.Fingerprints {
		expiry, err := observation.ExpiresAt[fingerprint].Float64()
		if err == nil && expiry > float64(domain.Unix(now)) {
			out.Fingerprints = append(out.Fingerprints, fingerprint)
			out.ExpiresAt[fingerprint] = domain.Timestamp(expiry)
		}
	}
	return out, last, nil
}
