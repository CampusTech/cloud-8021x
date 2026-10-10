package main

import (
	"errors"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
)

// Leaf and credential pins are independent immutable NAS inputs, never copied
// from observed server Class or SQL/intake output.
func deriveNASExpectations(p nasPrivatePlan, token string, key []byte, receipt, epoch time.Time) (expectations, error) {
	if !shaPattern.MatchString(p.ClientLeafSHA256) || !shaPattern.MatchString(p.Materials["class-key"]) || digestBytes(key) != p.Materials["class-key"] {
		return expectations{}, errors.New("independent NAS client/Class credential pins required")
	}
	identity := binding.Verify(key, []string{token}, "task11", []string{p.Station}, receipt, binding.MaxAge)
	if identity == nil || identity.Fingerprint != p.ClientLeafSHA256 {
		return expectations{}, errors.New("actual Class differs from independently pinned client leaf")
	}
	return deriveExpectations(p.Scenario, p.Station, token, key, receipt, epoch)
}
