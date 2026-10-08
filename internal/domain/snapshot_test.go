package domain

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestSnapshotLegacySchemaAndNormalization(t *testing.T) {
	d := Device{ID: "other:1", Identities: []string{" {0123456789ABCDEF0123456789ABCDEF} Campus WiFi ", "SERIAL"}, Groups: []GroupID{}, Enrolled: true}
	s, err := BuildSnapshot([]Device{d}, 100.125)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":1,"updated_at":100.125,"identities":{"01234567-89ab-cdef-0123-456789abcdef":{"device_id":"other:1","groups":[],"enrolled":true},"SERIAL":{"device_id":"other:1","groups":[],"enrolled":true}}}`
	got, _ := json.Marshal(s)
	var a, b any
	_ = json.Unmarshal(got, &a)
	_ = json.Unmarshal([]byte(want), &b)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("schema %s", got)
	}
	round, err := DecodeSnapshot(bytes.NewReader(got))
	if err != nil || !reflect.DeepEqual(s, round) {
		t.Fatalf("roundtrip %+v %v", round, err)
	}
}
func TestSnapshotV2PreservesCertificateTimesAndStickyAmbiguities(t *testing.T) {
	fp := strings.Repeat("AB", 32)
	fps := []string{fp}
	d := Device{ID: "fake:1", Identities: []string{"serial"}, HardwareSerial: "serial", Groups: []GroupID{"fake:staff"}, Enrolled: true, Fingerprints: &fps, CertificatesObservedAt: 90.25, Metadata: &DeviceMetadata{Name: "First"}}
	other := d
	other.ID = "fake:2"
	s, err := BuildSnapshot([]Device{d, other, d}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if s.Version != 2 || s.Identities["serial"] != nil || s.Certificates[strings.ToLower(fp)] != nil || s.HardwareSerials["serial"] != nil {
		t.Fatalf("ambiguity %+v", s)
	}
	other = d
	other.Metadata = &DeviceMetadata{Name: "Other"}
	s, err = BuildSnapshot([]Device{d, other, d}, 101)
	if err != nil {
		t.Fatal(err)
	}
	if s.Devices[d.ID] != nil || *s.Certificates[strings.ToLower(fp)].ObservedAt != 90.25 {
		t.Fatal("metadata ambiguity or observation refreshed")
	}
	raw, _ := json.Marshal(s)
	round, err := DecodeSnapshot(bytes.NewReader(raw))
	if err != nil || !reflect.DeepEqual(s, round) {
		t.Fatalf("v2 %s %v", raw, err)
	}
}
func TestSnapshotRejectsMalformedAndPartialPublication(t *testing.T) {
	for _, raw := range []string{`{"version":3,"updated_at":1,"identities":{}}`, `{"version":2,"updated_at":1,"identities":{},"certificates":{"invalid":null}}`, `{"version":1,"updated_at":1,"identities":{}} {}`, `{"version":1,"version":2,"updated_at":1,"identities":{}}`, `{"version":1,"updated_at":1,"identities":{"s":{"device_id":"d","groups":null,"enrolled":true}}}`} {
		if _, err := DecodeSnapshot(strings.NewReader(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	store := new(SnapshotStore)
	scope := InventoryScope{ProviderID: "fake", IDs: []string{"one"}}
	source := fakeDeviceProvider{DeviceSnapshot{Scope: scope, Complete: true, ObservedAt: 100, Devices: []Device{{ID: "fake:1", Groups: []GroupID{}, Identities: []string{"s"}, Enrolled: true}}}}
	batch, err := source.Fetch(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Publish(batch); err != nil {
		t.Fatal(err)
	}
	batch.Complete = false
	batch.ObservedAt = 200
	if err := store.Publish(batch); err == nil {
		t.Fatal("partial refresh published")
	}
	got := store.Load()
	if got.UpdatedAt != 100 {
		t.Fatal("partial refresh advanced time")
	}
	got.Identities["s"].Enrolled = false
	if !store.Load().Identities["s"].Enrolled {
		t.Fatal("mutable snapshot alias")
	}
}

type fakeDeviceProvider struct{ snapshot DeviceSnapshot }

func (p fakeDeviceProvider) Fetch(context.Context, InventoryScope) (DeviceSnapshot, error) {
	return p.snapshot, nil
}

var _ DeviceInventoryProvider = fakeDeviceProvider{}

func TestEmptyVersionTwoCertificateMapsArePresentAndBadMetadataIsOnlyDisplay(t *testing.T) {
	fps := []string{}
	s, err := BuildSnapshot([]Device{{ID: "other:1", Identities: []string{"s"}, Groups: []GroupID{}, Fingerprints: &fps}}, 100)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(s)
	if !bytes.Contains(raw, []byte(`"certificates":{}`)) || !bytes.Contains(raw, []byte(`"hardware_serials":{}`)) {
		t.Fatal("lost v2 empty maps", string(raw))
	}
	if _, err = DecodeSnapshot(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	raw = []byte(`{"version":1,"updated_at":100,"identities":{"s":{"device_id":"other:1","groups":[],"enrolled":true}},"devices":{"other:1":{"serial":"","device_name":7,"device_model":"","device_owner":""}}}`)
	s, err = DecodeSnapshot(bytes.NewReader(raw))
	if err != nil || s.Devices["other:1"] != nil || !s.Identities["s"].Enrolled {
		t.Fatal("display corrupted authorization", err)
	}
}
func TestMalformedSnapshotCannotRepairGroupsOrMissingObservation(t *testing.T) {
	for _, raw := range []string{`{"version":1,"identities":{}}`, `{"version":1,"updated_at":null,"identities":{}}`} {
		if _, err := DecodeSnapshot(strings.NewReader(raw)); err == nil {
			t.Fatal("missing timestamp accepted", raw)
		}
	}
	s := Snapshot{Version: 1, UpdatedAt: 100, Identities: map[string]*DeviceRecord{"s": {DeviceID: "other:1", Groups: nil, Enrolled: true}}}
	if s.Clone().Identities["s"].Groups != nil {
		t.Fatal("clone repaired malformed groups")
	}
	store := new(SnapshotStore)
	if err := store.Set(s); err == nil {
		t.Fatal("invalid snapshot accepted by store")
	}
}
func TestImmutableSnapshotViewOnlyCopiesSelectedRecordsAndRetainsGeneration(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	fps := []string{fp}
	s, err := BuildSnapshot([]Device{{ID: "other:1", Identities: []string{"s"}, Groups: []GroupID{"staff"}, Enrolled: true, Fingerprints: &fps, CertificatesObservedAt: 90}}, 100)
	if err != nil {
		t.Fatal(err)
	}
	store := new(SnapshotStore)
	if err := store.Set(s); err != nil {
		t.Fatal(err)
	}
	view := store.View()
	record := view.ByCertificate(fp)
	record.Enrolled = false
	record.Groups[0] = "spoofed"
	if !view.ByCertificate(fp).Enrolled || view.ByCertificate(fp).Groups[0] != "staff" {
		t.Fatal("view exposes mutable cached record")
	}
	s.UpdatedAt = 200
	if err := store.Set(s); err != nil {
		t.Fatal(err)
	}
	if view.Updated() != 100 || store.View().Updated() != 200 {
		t.Fatal("view generation is mutable")
	}
}
