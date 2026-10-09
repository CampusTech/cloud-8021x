package main

import (
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
)

func TestSemanticDisplayToleratesOnlyRenderingEquivalentRefresh(t *testing.T) {
	c := config.Defaults()
	s := domain.Snapshot{Version: 2, UpdatedAt: domain.Unix(time.Now().Add(-time.Minute)), Identities: map[string]*domain.DeviceRecord{}, Certificates: map[string]*domain.DeviceRecord{}, HardwareSerials: map[string]*domain.DeviceRecord{}, Devices: map[domain.DeviceID]*domain.DeviceMetadata{"fleet:1": {}, "fleet:2": {}}}
	first, err := semanticDisplay(c, s)
	if err != nil {
		t.Fatal(err)
	}
	s.UpdatedAt = domain.Unix(time.Now())
	next, err := semanticDisplay(c, s)
	if err != nil || next != first {
		t.Fatal("timestamp-only refresh changed equivalent display")
	}
	s.Devices["fleet:2"] = &domain.DeviceMetadata{Name: "new meaningful display"}
	if _, err := semanticDisplay(c, s); err == nil {
		t.Fatal("changed historical display inferred without proof")
	}
}
