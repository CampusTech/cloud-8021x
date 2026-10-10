package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestImmutablePlanEpochRequiresExplicitUTCWholeSecondSelection(t *testing.T) {
	selected := time.Unix(1800000000, 0).UTC()
	for name, epoch := range map[string]time.Time{
		"missing":    {},
		"fractional": selected.Add(time.Nanosecond),
		"non-UTC":    selected.In(time.FixedZone("foreign", 3600)),
	} {
		t.Run(name, func(t *testing.T) {
			p := fixturePlan()
			p.CollectionEpoch = epoch
			if validatePlan(p) == nil {
				t.Fatal("unselected or non-UTC whole-second epoch accepted")
			}
		})
	}
	// The selected UTC instant is not tied to a time.Location pointer. A decoded
	// +00:00 value and an equivalent named zero-offset zone retain the same pin.
	for _, epoch := range []time.Time{selected, selected.In(time.FixedZone("zero", 0))} {
		p := fixturePlan()
		p.CollectionEpoch = epoch
		if e := validatePlan(p); e != nil {
			t.Fatal(e)
		}
	}
	p := pureNASPlan()
	raw, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := decodeNASPlan(raw, digestBytes(raw))
	if e != nil {
		t.Fatal(e)
	}
	if !decoded.Scenario.CollectionEpoch.Equal(selected) {
		t.Fatal("exact independently selected epoch lost")
	}
}

func TestNASExpectationRefusesCallerEpochSubstitution(t *testing.T) {
	receipt := time.Unix(1800000000, 0).UTC()
	key, token := actualClassForPureTest(t, receipt)
	p := pureNASPlan()
	p.Materials["class-key"] = digestBytes(key)
	selected := p.Scenario.CollectionEpoch
	if _, e := deriveNASExpectations(p, token, key, receipt, selected); e != nil {
		t.Fatal(e)
	}
	for _, other := range []time.Time{{}, selected.Add(-time.Second), selected.Add(time.Nanosecond)} {
		if _, e := deriveNASExpectations(p, token, key, receipt, other); e == nil {
			t.Fatal("caller/receipt epoch replaced immutable planned epoch")
		}
		if _, e := deriveExpectations(p.Scenario, p.Station, token, key, receipt, other); e == nil {
			t.Fatal("low-level expectation path bypassed immutable planned epoch")
		}
	}
}
