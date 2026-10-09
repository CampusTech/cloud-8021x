package main

import (
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/telemetry"
)

// The two fixed synthetic API hosts intentionally supply no optional display
// data. Prove the actual renderer is freshness-insensitive for that exact scope;
// meaningful names/serials or network providers require new historical evidence.
func semanticDisplay(c config.Config, s domain.Snapshot) (string, error) {
	if len(c.Network.Providers) != 0 || c.Policy.InventoryMaxAge < time.Second {
		return "", errors.New("display source scope differs")
	}
	for id, m := range s.Devices {
		if id != "fleet:1" && id != "fleet:2" {
			return "", errors.New("display identity outside reviewed seed")
		}
		if m == nil {
			continue
		}
		for _, v := range []string{m.Serial, m.Name, m.Model, m.Owner} {
			if v != "" && v != "N/A" {
				return "", errors.New("meaningful display changes need exact historical send context")
			}
		}
	}
	expected := map[string]any{"device_owner": "N/A", "device_name": "N/A", "device_model": "N/A", "serial": "N/A"}
	for _, id := range []domain.DeviceID{"fleet:1", "fleet:2"} {
		for _, stamp := range []domain.Timestamp{s.UpdatedAt, domain.Unix(time.Now().Add(-time.Millisecond)), 0} {
			snapshot := s.Clone()
			snapshot.UpdatedAt = stamp
			store := &domain.SnapshotStore{}
			if err := store.Set(snapshot); err != nil {
				return "", err
			}
			r := telemetry.BusinessRecord{Fields: map[string]any{"device_owner": "N/A", "device_name": "N/A", "device_model": "N/A", "serial": "N/A"}}
			telemetry.NewDisplay(c, store, nil).Enrich(&r, "", "", &binding.Attribution{DeviceID: id})
			if !reflect.DeepEqual(r.Fields, expected) {
				return "", errors.New("actual display freshness changes rendered fields")
			}
		}
	}
	raw, err := json.Marshal(expected)
	if err != nil {
		return "", err
	}
	return adoption.Digest(raw), nil
}
