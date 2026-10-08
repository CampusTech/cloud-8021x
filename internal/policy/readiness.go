package policy

import (
	"math"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

// Providers classify unsupported collection capabilities before entering neutral
// readiness. IDs and ineligibility reasons retain the adapter's original provenance.
type ReadinessDevice struct {
	ID               domain.DeviceID
	Enrolled         bool
	IneligibleReason string
}
type LocationReadiness struct {
	Reason       string `json:"reason"`
	VLAN         *int   `json:"vlan"`
	DynamicVLANs bool   `json:"dynamic_vlans"`
}
type DeviceReadiness struct {
	ID                domain.DeviceID                         `json:"device_id"`
	Reason            string                                  `json:"reason"`
	CertificateReason string                                  `json:"certificate_reason"`
	Locations         map[domain.LocationID]LocationReadiness `json:"locations,omitempty"`
}
type ReadinessReport struct {
	Ready          bool              `json:"ready"`
	ReadyCount     int               `json:"ready_count"`
	Total          int               `json:"total"`
	UpdatedAt      domain.Timestamp  `json:"updated_at"`
	MaxAge         float64           `json:"max_age"`
	PolicyEnforced bool              `json:"policy_enforced"`
	Devices        []DeviceReadiness `json:"devices"`
}

// CertificateReadiness separates observed certificate coverage from current VLAN
// readiness. It cannot construct a VerifiedCertificate or authorize a live session.
func CertificateReadiness(devices []ReadinessDevice, observations map[domain.DeviceID]domain.CertificateObservation, snapshot domain.Snapshot, engine *Engine, now time.Time) ReadinessReport {
	report := ReadinessReport{Total: len(devices), UpdatedAt: domain.Unix(now), MaxAge: engine.config.CertificateMaxAge.Seconds(), PolicyEnforced: engine.config.IdentityMode == FingerprintMode, Devices: []DeviceReadiness{}}
	counts := map[domain.DeviceID]int{}
	owners := map[string]int{}
	for _, d := range devices {
		counts[d.ID]++
	}
	for _, obs := range observations {
		unique := map[string]bool{}
		for _, fp := range obs.Fingerprints {
			unique[fp] = true
		}
		for fp := range unique {
			owners[fp]++
		}
	}
	for _, d := range devices {
		obs, hasObs := observations[d.ID]
		reason := "ready"
		age := float64(domain.Unix(now) - obs.ObservedAt)
		switch {
		case d.ID == "" || counts[d.ID] != 1:
			reason = "ambiguous_host_identity"
		case d.IneligibleReason != "":
			reason = d.IneligibleReason
		case !d.Enrolled:
			reason = "not_enrolled"
		case !hasObs:
			reason = "no_certificate_observation"
		case math.IsNaN(age) || math.IsInf(age, 0) || age < 0 || age > engine.config.CertificateMaxAge.Seconds():
			reason = "stale_certificate_observation"
		case len(obs.Fingerprints) == 0:
			reason = "no_managed_identity"
		default:
			for _, fp := range obs.Fingerprints {
				if owners[fp] != 1 {
					reason = "ambiguous_certificate_identity"
					break
				}
			}
			if reason == "ready" && !obs.TrustVerified {
				reason = "certificate_observed_trust_unverified"
			}
			if reason == "ready" {
				unexpired := false
				for _, fp := range obs.Fingerprints {
					if obs.ExpiresAt[fp] > domain.Unix(now) {
						unexpired = true
					}
				}
				if !unexpired {
					reason = "expired_certificate_identity"
				}
			}
		}
		row := DeviceReadiness{ID: d.ID, Reason: reason, CertificateReason: reason}
		if reason == "ready" {
			row.Locations = map[domain.LocationID]LocationReadiness{}
			for _, location := range engine.config.Locations {
				result := LocationReadiness{Reason: "ready", DynamicVLANs: location.VLANEnabled}
				selected := -1
				for _, fp := range obs.Fingerprints {
					normalized, err := domain.NormalizeFingerprint(fp)
					record := snapshot.Certificates[normalized]
					if err != nil || snapshot.Version != 2 || !domain.Fresh(snapshot.UpdatedAt, now, engine.config.InventoryMaxAge) || record == nil || record.DeviceID != d.ID || !record.Enrolled || record.Groups == nil || record.ObservedAt == nil || !domain.Fresh(*record.ObservedAt, now, engine.config.CertificateMaxAge) {
						result.Reason = "no_vlan_assignment"
						break
					}
					decision, err := engine.selectVLAN(record, normalized, domain.TrustedNetworkContext{ClientID: "readiness", LocationID: location.ID, Medium: domain.WiFi})
					if err != nil {
						result.Reason = "no_vlan_assignment"
						break
					}
					vlan := 0
					if decision.VLAN != nil {
						vlan = decision.VLAN.ID
					}
					if selected != -1 && selected != vlan {
						result.Reason = "no_vlan_assignment"
						break
					}
					selected = vlan
				}
				if result.Reason == "ready" && selected > 0 {
					vlan := selected
					result.VLAN = &vlan
				}
				if result.Reason != "ready" {
					row.Reason = "no_vlan_assignment"
				}
				row.Locations[location.ID] = result
			}
		}
		if row.Reason == "ready" {
			report.ReadyCount++
		}
		report.Devices = append(report.Devices, row)
	}
	report.Ready = report.Total > 0 && report.ReadyCount == report.Total
	return report
}
