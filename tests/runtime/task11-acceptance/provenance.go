package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"reflect"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/migration"
)

// Public, minimal projection of the approved original cache. The retained
// private commands/state never become readable by the unprivileged service.
type sourceProvenance struct {
	Schema                 int
	CertificateStateSHA256 string
	EnrollmentSHA256       string
	Snapshot               domain.Snapshot
}

func deriveSourceProvenance(raw, certificates []byte) (sourceProvenance, error) {
	var p sourceProvenance
	if err := validateSourceCache(raw); err != nil {
		return p, err
	}
	s, err := domain.DecodeSnapshot(bytes.NewReader(raw))
	if err != nil {
		return p, err
	}
	state, err := migration.DecodeCertificates(certificates)
	if err != nil {
		return p, err
	}
	h, ok := state.Hosts[syntheticDevice]
	if !ok || len(state.Hosts) != 1 || h.Platform != "darwin" || h.Observation == nil || !h.Observation.TrustVerified || len(h.Observation.Fingerprints) != 1 || state.Trust == nil || len(h.Binding) != 3 {
		return p, errors.New("approved original certificate/enrollment provenance required")
	}
	var id int
	if json.Unmarshal(h.Binding[0], &id) != nil || id != 1 {
		return p, errors.New("original Fleet host differs")
	}
	enrolled, err := migration.ReceiptTime(h.Binding[1])
	if err != nil {
		return p, err
	}
	fleetEnrollment, err := migration.ReceiptTime(h.Binding[2])
	if err != nil {
		return p, err
	}
	observed, err := migration.ReceiptTime([]byte(h.Observation.ObservedAt))
	if err != nil {
		return p, err
	}
	fp := h.Observation.Fingerprints[0]
	rec := s.Certificates[fp]
	if rec == nil || rec.ObservedAt == nil || *rec.ObservedAt != domain.Unix(observed) || !reflect.DeepEqual(s.Identities[syntheticDevice], rec) || enrolled.After(observed) || fleetEnrollment.After(observed) || s.UpdatedAt < domain.Unix(observed) || math.IsNaN(float64(s.UpdatedAt)) || math.IsInf(float64(s.UpdatedAt), 0) {
		return p, errors.New("original identity/fingerprint/observation/enrollment differs")
	}
	expiry, err := migration.ReceiptTime([]byte(h.Observation.ExpiresAt[fp]))
	if err != nil || !expiry.After(observed) {
		return p, errors.New("original certificate expiry unavailable")
	}
	binding, err := json.Marshal(h.Binding)
	if err != nil {
		return p, err
	}
	p = sourceProvenance{Schema: 1, CertificateStateSHA256: adoption.Digest(certificates), EnrollmentSHA256: adoption.Digest(binding), Snapshot: s}
	return p, nil
}
func validateBoundSourceCache(raw []byte, p sourceProvenance) error {
	if p.Schema != 1 || len(p.CertificateStateSHA256) != 64 || len(p.EnrollmentSHA256) != 64 {
		return errors.New("approved root source projection missing")
	}
	if err := validateSourceCache(raw); err != nil {
		return err
	}
	s, err := domain.DecodeSnapshot(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	if s.UpdatedAt > p.Snapshot.UpdatedAt || s.UpdatedAt < 0 || math.IsNaN(float64(s.UpdatedAt)) || math.IsInf(float64(s.UpdatedAt), 0) {
		return errors.New("source inventory freshness advanced beyond approved original")
	}
	// Only backdating inventory freshness is an explicit stale-negative input.
	// Identity/certificate observations, groups and enrollment remain exact.
	s.UpdatedAt = p.Snapshot.UpdatedAt
	if !reflect.DeepEqual(s, p.Snapshot) {
		return errors.New("source identity or certificate provenance changed")
	}
	return nil
}
