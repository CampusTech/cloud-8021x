package migration

import (
	"encoding/json"
	"errors"
	"slices"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

type legacyReadinessLocation struct {
	Reason  string `json:"reason"`
	VLAN    *int   `json:"vlan,omitempty"`
	Dynamic *bool  `json:"dynamic_vlans,omitempty"`
}
type legacyReadinessHost struct {
	ID                *uint64                            `json:"id"`
	UUID              *string                            `json:"uuid"`
	Reason            string                             `json:"reason"`
	CertificateReason string                             `json:"certificate_reason"`
	Locations         map[string]legacyReadinessLocation `json:"locations,omitempty"`
	VLAN              *int                               `json:"vlan,omitempty"`
	Dynamic           *bool                              `json:"dynamic_vlans,omitempty"`
}
type legacyReadiness struct {
	Ready      *bool                 `json:"ready"`
	ReadyCount int                   `json:"ready_count"`
	Generated  json.Number           `json:"generated_at"`
	Updated    json.Number           `json:"updated_at"`
	MaxAge     json.Number           `json:"max_age"`
	Total      int                   `json:"total"`
	Hosts      []legacyReadinessHost `json:"hosts"`
	Enforced   *bool                 `json:"policy_enforced"`
}

func validateReadiness(raw []byte) error {
	var r legacyReadiness
	bad := errors.New("invalid retained readiness report")
	if len(raw) > 16<<20 || domain.DecodeJSONStrict(raw, &r) != nil || r.Ready == nil || r.Enforced == nil || r.Hosts == nil || len(r.Hosts) > 100000 || r.Total != len(r.Hosts) || r.ReadyCount < 0 || r.ReadyCount > r.Total || originalTime(r.Generated) != nil || originalTime(r.Updated) != nil || originalTime(r.MaxAge) != nil {
		return bad
	}
	generated, _ := ReceiptTime([]byte(r.Generated))
	updated, _ := ReceiptTime([]byte(r.Updated))
	if !generated.Equal(updated) {
		return bad
	}
	reasons := []string{"ambiguous_host_identity", "unsupported_platform", "not_enrolled", "fleet_scripts_unavailable", "no_certificate_observation", "stale_certificate_observation", "no_managed_identity", "ambiguous_certificate_identity", "certificate_observed_trust_unverified", "expired_certificate_identity", "ready"}
	locationValid := func(l legacyReadinessLocation) bool {
		return (l.Reason == "ready" || l.Reason == "no_vlan_assignment") && (l.VLAN == nil || domain.ValidVLAN(*l.VLAN)) && (l.Dynamic == nil || !*l.Dynamic && l.VLAN == nil)
	}
	ready := 0
	for _, h := range r.Hosts {
		if (h.UUID != nil && len(*h.UUID) > 253) || !slices.Contains(reasons, h.CertificateReason) || (!slices.Contains(reasons, h.Reason) && h.Reason != "no_vlan_assignment") || len(h.Locations) > 128 || (h.VLAN != nil && !domain.ValidVLAN(*h.VLAN)) || (h.Dynamic != nil && (*h.Dynamic || h.VLAN != nil)) {
			return bad
		}
		if h.Reason == "ready" {
			ready++
		}
		for id, loc := range h.Locations {
			if id == "" || len(id) > 253 || !locationValid(loc) {
				return bad
			}
		}
	}
	if ready != r.ReadyCount || *r.Ready != (r.Total > 0 && ready == r.Total) {
		return bad
	}
	return nil
}
