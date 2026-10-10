package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	fleetadapter "github.com/CampusTech/cloud-8021x/internal/adapters/fleet"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/inventory"
	"github.com/CampusTech/cloud-8021x/internal/migration"
	"howett.net/plist"
)

func inheritedNumber(at time.Time) json.Number {
	return json.Number(strconv.FormatFloat(float64(domain.Unix(at)), 'f', 6, 64))
}

func TestPostgresInheritedCollectionPeerOrderingAndPrivileges(t *testing.T) {
	admin, c := integration(t)
	reset(t, admin)
	ctx := context.Background()
	runtime := runtimeStore(t, admin, c)
	now := time.Now().UTC().Truncate(time.Microsecond)
	trust, _, ca := collectionTrustMaterial(t)
	trustDigest := sha256.Sum256(ca)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("current inherited attempt cadence allowed duplicate POST")
			w.WriteHeader(500)
			return
		}
		h := map[string]any{"id": 1, "uuid": "host", "platform": "ios", "os_version": "iOS 18.0", "last_mdm_enrolled_at": now.Add(-30 * time.Minute).Format(time.RFC3339Nano), "mdm": map[string]any{"enrollment_status": "On (manual)"}}
		if r.URL.Path == "/api/v1/fleet/hosts" {
			_ = json.NewEncoder(w).Encode(map[string]any{"hosts": []any{h}})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]any{"host": h})
		}
	}))
	defer server.Close()
	client, err := fleetadapter.NewClient(server.URL, "maintainer", server.Client(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	original := migration.LegacyCertificateState{Version: 1, Source: server.URL, Trust: new(hex.EncodeToString(trustDigest[:])), Hosts: map[string]migration.LegacyCertificateHost{"host": {Platform: "ios", Binding: []json.RawMessage{json.RawMessage("1"), json.RawMessage(inheritedNumber(now.Add(-4 * time.Hour))), json.RawMessage("null")}, LastAttempt: inheritedNumber(now.Add(-time.Minute)), Observation: &migration.LegacyCertificateObservation{Fingerprints: []string{strings.Repeat("b", 64)}, ObservedAt: inheritedNumber(now.Add(-2 * time.Hour)), TrustVerified: true, ExpiresAt: map[string]json.Number{strings.Repeat("b", 64): inheritedNumber(now.Add(time.Hour))}}}}, Commands: []migration.LegacyCommand{}}
	importState := func(state migration.LegacyCertificateState) error {
		tx, err := admin.begin(ctx)
		if err != nil {
			return err
		}
		defer rollback(tx)
		if err = importInheritedCollections(ctx, tx, state); err != nil {
			return err
		}
		return commit(ctx, tx)
	}
	newerRaw, _ := json.Marshal(original)
	var newer migration.LegacyCertificateState
	_ = json.Unmarshal(newerRaw, &newer)
	newer.Hosts["host"].Observation.Fingerprints = []string{}
	newer.Hosts["host"].Observation.ExpiresAt = nil
	newer.Hosts["host"].Observation.ObservedAt = inheritedNumber(now.Add(-time.Hour))
	newerHost := newer.Hosts["host"]
	newerHost.LastAttempt = inheritedNumber(now.Add(-3 * time.Minute))
	newer.Hosts["host"] = newerHost
	for _, order := range [][]migration.LegacyCertificateState{{original, newer}, {newer, original}} {
		reset(t, admin)
		for _, state := range order {
			if err := importState(state); err != nil {
				t.Fatal(err)
			}
		}
		scope := migration.LegacyCollectionScope(original.Source, 1, "host")
		raw, err := runtime.InheritedCollection(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		state, err := migration.DecodeCertificates(raw)
		if err != nil || len(state.Hosts["host"].Observation.Fingerprints) != 0 || state.Hosts["host"].Observation.ObservedAt != newer.Hosts["host"].Observation.ObservedAt || state.Hosts["host"].LastAttempt != original.Hosts["host"].LastAttempt {
			t.Fatalf("peer order changed inherited observation: %s %v", raw, err)
		}
	}
	// A peer that has a new enrollment but no result still carries original
	// attempt cadence. An older binding's observation cannot erase that state.
	currentRaw, _ := json.Marshal(original)
	var current migration.LegacyCertificateState
	_ = json.Unmarshal(currentRaw, &current)
	currentHost := current.Hosts["host"]
	currentHost.Binding[1] = json.RawMessage(inheritedNumber(now.Add(-30 * time.Minute)))
	currentHost.LastAttempt = inheritedNumber(now.Add(-30 * time.Second))
	currentHost.Observation = nil
	current.Hosts["host"] = currentHost
	olderPendingRaw, _ := json.Marshal(original)
	var olderPending migration.LegacyCertificateState
	_ = json.Unmarshal(olderPendingRaw, &olderPending)
	olderPendingHost := olderPending.Hosts["host"]
	olderPendingHost.Observation = nil
	olderPending.Hosts["host"] = olderPendingHost
	for _, order := range [][]migration.LegacyCertificateState{{original, current}, {current, original}, {olderPending, current}, {current, olderPending}} {
		reset(t, admin)
		for _, state := range order {
			if err := importState(state); err != nil {
				t.Fatal(err)
			}
		}
		raw, err := runtime.InheritedCollection(ctx, migration.LegacyCollectionScope(original.Source, 1, "host"))
		if err != nil {
			t.Fatal(err)
		}
		state, err := migration.DecodeCertificates(raw)
		if err != nil || state.Hosts["host"].Observation != nil || state.Hosts["host"].LastAttempt != currentHost.LastAttempt {
			t.Fatalf("new enrollment without result lost original attempt cadence: %s %v", raw, err)
		}
		collector := &fleetadapter.Collector{Maintainer: client, Repository: runtime, Trust: trust, Now: func() time.Time { return now }}
		batch := domain.DeviceSnapshot{Scope: domain.InventoryScope{ProviderID: "fleet", IDs: []string{"1"}}, Complete: true, ObservedAt: domain.Unix(now), Devices: []domain.Device{{ID: "fleet:1", Identities: []string{"host"}, Groups: []domain.GroupID{}, Enrolled: true}}}
		if err := collector.Prepare(ctx, batch); err != nil {
			t.Fatal(err)
		}
		if _, err := collector.Collect(ctx, domain.CertificateCollectionRequest{DeviceID: "fleet:1"}); !errors.Is(err, inventory.ErrPending) {
			t.Fatalf("superseded observation authorized current binding: %v", err)
		}
		if count(t, admin, "work") != 0 || count(t, admin, "attempts") != 0 {
			t.Fatal("current original attempt cadence was not retained")
		}
	}
	// Equal original activity cannot choose between conflicting bindings.
	ambiguousRaw, _ := json.Marshal(current)
	var ambiguous migration.LegacyCertificateState
	_ = json.Unmarshal(ambiguousRaw, &ambiguous)
	ambiguousHost := ambiguous.Hosts["host"]
	ambiguousHost.LastAttempt = original.Hosts["host"].LastAttempt
	ambiguous.Hosts["host"] = ambiguousHost
	for _, order := range [][]migration.LegacyCertificateState{{original, ambiguous}, {ambiguous, original}} {
		reset(t, admin)
		if err := importState(order[0]); err != nil {
			t.Fatal(err)
		}
		if err := importState(order[1]); err == nil {
			t.Fatal("equal original activity accepted conflicting bindings")
		}
	}
	reset(t, admin)
	if err := importState(newer); err != nil {
		t.Fatal(err)
	}
	conflictingRaw, _ := json.Marshal(newer)
	var conflicting migration.LegacyCertificateState
	_ = json.Unmarshal(conflictingRaw, &conflicting)
	conflicting.Hosts["host"].Observation.Fingerprints = []string{strings.Repeat("c", 64)}
	if err := importState(conflicting); err == nil {
		t.Fatal("same-time conflicting content accepted")
	}
	conflictingRaw, _ = json.Marshal(newer)
	_ = json.Unmarshal(conflictingRaw, &conflicting)
	h := conflicting.Hosts["host"]
	h.Binding[1] = json.RawMessage(inheritedNumber(now.Add(-3 * time.Hour)))
	conflicting.Hosts["host"] = h
	if err := importState(conflicting); err == nil {
		t.Fatal("same-time conflicting enrollment accepted")
	}
	for _, q := range []string{`INSERT INTO ledger.inherited_certificates VALUES('forged','forged')`, `UPDATE ledger.inherited_certificates SET document='forged'`, `DELETE FROM ledger.inherited_certificates`} {
		if _, err := runtime.pool.Exec(ctx, q); err == nil {
			t.Fatal("runtime mutated inherited authority", q)
		}
	}
	native := roleStore(t, c, "app_native", "disposable-native")
	if _, err := native.InheritedCollection(ctx, migration.LegacyCollectionScope(original.Source, 1, "host")); err == nil {
		t.Fatal("native read inherited certificate authority")
	}
	if count(t, admin, "work") != 0 || count(t, admin, "attempts") != 0 {
		t.Fatal("import manufactured collection history")
	}
}

func TestPostgresInheritedCollectionRequiresCurrentBinding(t *testing.T) {
	admin, c := integration(t)
	ctx := context.Background()
	runtime := runtimeStore(t, admin, c)
	trust, _, ca := collectionTrustMaterial(t)
	digest := sha256.Sum256(ca)
	script, err := os.ReadFile("../../adapters/fleet/windows_certificates.ps1")
	if err != nil {
		t.Fatal(err)
	}
	scriptDigest := sha256.Sum256(script)
	now := time.Now().UTC().Truncate(time.Microsecond)
	enrollment := now.Add(-2 * time.Hour).Add(789 * time.Nanosecond)
	fp := strings.Repeat("b", 64)
	platform := "ios"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("inherited cadence manufactured a remote attempt")
			w.WriteHeader(500)
			return
		}
		h := map[string]any{"id": 1, "uuid": "host", "platform": platform, "os_version": "iOS 18.0", "scripts_enabled": true, "last_mdm_enrolled_at": enrollment.Format(time.RFC3339Nano), "mdm": map[string]any{"enrollment_status": "On (manual)"}}
		if platform == "windows" {
			h["last_enrolled_at"] = enrollment.Format(time.RFC3339Nano)
		}
		if r.URL.Path == "/api/v1/fleet/hosts" {
			_ = json.NewEncoder(w).Encode(map[string]any{"hosts": []any{h}})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]any{"host": h})
		}
	}))
	defer server.Close()
	client, err := fleetadapter.NewClient(server.URL, "maintainer", server.Client(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name                     string
		windows, accepted, empty bool
		mutate                   func(*migration.LegacyCertificateState)
	}{
		{name: "original", accepted: true},
		{name: "old observation keeps last attempt cadence", accepted: true, mutate: func(s *migration.LegacyCertificateState) {
			s.Hosts["host"].Observation.ObservedAt = inheritedNumber(now.Add(-90 * time.Minute))
		}},
		{name: "trust changed", mutate: func(s *migration.LegacyCertificateState) { s.Trust = new(strings.Repeat("c", 64)) }},
		{name: "source changed", mutate: func(s *migration.LegacyCertificateState) { s.Source = "https://other.invalid" }},
		{name: "UUID changed", mutate: func(s *migration.LegacyCertificateState) { s.Hosts["other"] = s.Hosts["host"]; delete(s.Hosts, "host") }},
		{name: "numeric ID changed", mutate: func(s *migration.LegacyCertificateState) {
			h := s.Hosts["host"]
			h.Binding[0] = json.RawMessage("2")
			s.Hosts["host"] = h
		}},
		{name: "platform changed", mutate: func(s *migration.LegacyCertificateState) {
			h := s.Hosts["host"]
			h.Platform = "ipados"
			s.Hosts["host"] = h
		}},
		{name: "enrollment changed", mutate: func(s *migration.LegacyCertificateState) {
			h := s.Hosts["host"]
			h.Binding[1] = json.RawMessage(inheritedNumber(now.Add(-time.Hour)))
			s.Hosts["host"] = h
		}},
		{name: "null Fleet enrollment differs", mutate: func(s *migration.LegacyCertificateState) {
			h := s.Hosts["host"]
			h.Binding[2], _ = json.Marshal(enrollment.Format(time.RFC3339Nano))
			s.Hosts["host"] = h
		}},
		{name: "expired", accepted: true, empty: true, mutate: func(s *migration.LegacyCertificateState) {
			s.Hosts["host"].Observation.ExpiresAt[fp] = inheritedNumber(now.Add(-time.Second))
		}},
		{name: "missing expiry", accepted: true, empty: true, mutate: func(s *migration.LegacyCertificateState) { s.Hosts["host"].Observation.ExpiresAt = nil }},
		{name: "unverified", mutate: func(s *migration.LegacyCertificateState) { s.Hosts["host"].Observation.TrustVerified = false }},
		{name: "stale", mutate: func(s *migration.LegacyCertificateState) {
			s.Hosts["host"].Observation.ObservedAt = inheritedNumber(now.Add(-25 * time.Hour))
		}},
		{name: "future", mutate: func(s *migration.LegacyCertificateState) {
			s.Hosts["host"].Observation.ObservedAt = inheritedNumber(now.Add(time.Second))
		}},
		{name: "before enrollment", mutate: func(s *migration.LegacyCertificateState) {
			s.Hosts["host"].Observation.ObservedAt = inheritedNumber(enrollment.Add(-time.Second))
		}},
		{name: "Windows script", windows: true, accepted: true},
		{name: "Windows script changed", windows: true, mutate: func(s *migration.LegacyCertificateState) {
			h := s.Hosts["host"]
			h.Binding[3], _ = json.Marshal(strings.Repeat("c", 64))
			s.Hosts["host"] = h
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reset(t, admin)
			platform = "ios"
			binding := []json.RawMessage{json.RawMessage("1"), json.RawMessage(inheritedNumber(enrollment.Truncate(time.Microsecond))), json.RawMessage("null")}
			if tc.windows {
				platform = "windows"
				binding[2], _ = json.Marshal(enrollment.Format(time.RFC3339Nano))
				value, _ := json.Marshal(hex.EncodeToString(scriptDigest[:]))
				binding = append(binding, value)
			}
			state := migration.LegacyCertificateState{Version: 1, Source: server.URL, Trust: new(hex.EncodeToString(digest[:])), Hosts: map[string]migration.LegacyCertificateHost{"host": {Binding: binding, Platform: platform, LastAttempt: inheritedNumber(now.Add(-time.Minute)), Observation: &migration.LegacyCertificateObservation{Fingerprints: []string{fp}, ObservedAt: inheritedNumber(now.Add(-10 * time.Minute)), TrustVerified: true, ExpiresAt: map[string]json.Number{fp: inheritedNumber(now.Add(time.Hour))}}}}, Commands: []migration.LegacyCommand{}}
			if tc.accepted && tc.mutate != nil {
				tc.mutate(&state)
			}
			raw, _ := json.Marshal(state)
			scope := migration.LegacyCollectionScope(server.URL, 1, "host")
			if _, err := admin.pool.Exec(ctx, `INSERT INTO ledger.inherited_certificates(scope,document) VALUES($1,$2)`, scope, raw); err != nil {
				t.Fatal(err)
			}
			collector := &fleetadapter.Collector{Maintainer: client, Repository: runtime, Trust: trust, Now: func() time.Time { return now }}
			batch := domain.DeviceSnapshot{Scope: domain.InventoryScope{ProviderID: "fleet", IDs: []string{"1"}}, Complete: true, ObservedAt: domain.Unix(now), Devices: []domain.Device{{ID: "fleet:1", Identities: []string{"host"}, Groups: []domain.GroupID{}, Enrolled: true}}}
			if err := collector.Prepare(ctx, batch); err != nil {
				t.Fatal(err)
			}
			// A peer cache change after preparation must be checked again at collection.
			if !tc.accepted && tc.mutate != nil {
				tc.mutate(&state)
			}
			raw, _ = json.Marshal(state)
			if _, err := admin.pool.Exec(ctx, `UPDATE ledger.inherited_certificates SET document=$2 WHERE scope=$1`, scope, raw); err != nil {
				t.Fatal(err)
			}
			observation, err := collector.Collect(ctx, domain.CertificateCollectionRequest{DeviceID: "fleet:1"})
			if tc.accepted {
				expected, _ := state.Hosts["host"].Observation.ObservedAt.Float64()
				wantedCount := 1
				if tc.empty {
					wantedCount = 0
				}
				if err != nil || len(observation.Fingerprints) != wantedCount || (wantedCount == 1 && observation.Fingerprints[0] != fp) || observation.ObservedAt != domain.Timestamp(expected) || !strings.HasPrefix(observation.Provenance, "inherited-handoff:") {
					t.Fatalf("original observation changed: %+v %v", observation, err)
				}
			} else if !errors.Is(err, inventory.ErrPending) {
				t.Fatalf("changed inherited authority accepted: %+v %v", observation, err)
			}
			if count(t, admin, "work") != 0 || count(t, admin, "attempts") != 0 {
				t.Fatal("inherited observation manufactured attempt history")
			}
		})
	}
}

func TestPostgresInheritedCollectionYieldsToNewerEmptyFleetReceipt(t *testing.T) {
	admin, c := integration(t)
	reset(t, admin)
	ctx := context.Background()
	runtime := runtimeStore(t, admin, c)
	trust, _, ca := collectionTrustMaterial(t)
	digest := sha256.Sum256(ca)
	now := time.Now().UTC().Truncate(time.Second)
	enrollment := now.Add(-4 * time.Hour)
	fp := strings.Repeat("b", 64)
	command := ""
	posts := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := map[string]any{"id": 1, "uuid": "host", "platform": "ios", "os_version": "iOS 18.0", "last_mdm_enrolled_at": enrollment.Format(time.RFC3339Nano), "mdm": map[string]any{"enrollment_status": "On (manual)"}}
		switch r.URL.Path {
		case "/api/v1/fleet/hosts":
			_ = json.NewEncoder(w).Encode(map[string]any{"hosts": []any{h}})
		case "/api/v1/fleet/hosts/1":
			_ = json.NewEncoder(w).Encode(map[string]any{"host": h})
		case "/api/v1/fleet/commands/run":
			var body struct {
				Command string `json:"command"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			data, err := base64.StdEncoding.DecodeString(body.Command)
			if err != nil {
				t.Error(err)
			}
			var payload struct {
				UUID string `plist:"CommandUUID"`
			}
			if _, err = plist.Unmarshal(data, &payload); err != nil {
				t.Error(err)
			}
			command = payload.UUID
			posts++
			_ = json.NewEncoder(w).Encode(map[string]any{"command_uuid": command, "request_type": "CertificateList"})
		case "/api/v1/fleet/commands/results":
			data, _ := plist.Marshal(map[string]any{"CommandUUID": command, "UDID": "host", "Status": "Acknowledged", "CertificateList": []any{}}, plist.BinaryFormat)
			_ = json.NewEncoder(w).Encode(map[string]any{"results": []any{map[string]any{"host_uuid": "host", "command_uuid": command, "request_type": "CertificateList", "status": "Acknowledged", "updated_at": now.Format(time.RFC3339Nano), "result": base64.StdEncoding.EncodeToString(data)}}})
		default:
			t.Errorf("unexpected Fleet request %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	original := migration.LegacyCertificateState{Version: 1, Source: server.URL, Trust: new(hex.EncodeToString(digest[:])), Hosts: map[string]migration.LegacyCertificateHost{"host": {Platform: "ios", Binding: []json.RawMessage{json.RawMessage("1"), json.RawMessage(inheritedNumber(enrollment)), json.RawMessage("null")}, LastAttempt: inheritedNumber(now.Add(-2 * time.Hour)), Observation: &migration.LegacyCertificateObservation{Fingerprints: []string{fp}, ObservedAt: inheritedNumber(now.Add(-2 * time.Hour)), TrustVerified: true, ExpiresAt: map[string]json.Number{fp: inheritedNumber(now.Add(time.Hour))}}}}, Commands: []migration.LegacyCommand{}}
	tx, err := admin.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	if err = importInheritedCollections(ctx, tx, original); err != nil {
		t.Fatal(err)
	}
	if err = commit(ctx, tx); err != nil {
		t.Fatal(err)
	}
	client, err := fleetadapter.NewClient(server.URL, "maintainer", server.Client(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	collector := &fleetadapter.Collector{Maintainer: client, Repository: runtime, Trust: trust, Now: func() time.Time { return now }}
	batch := domain.DeviceSnapshot{Scope: domain.InventoryScope{ProviderID: "fleet", IDs: []string{"1"}}, Complete: true, ObservedAt: domain.Unix(now), Devices: []domain.Device{{ID: "fleet:1", Identities: []string{"host"}, Groups: []domain.GroupID{}, Enrolled: true}}}
	if err = collector.Prepare(ctx, batch); err != nil {
		t.Fatal(err)
	}
	request := domain.CertificateCollectionRequest{DeviceID: "fleet:1"}
	inherited, err := collector.Collect(ctx, request)
	if err != nil || len(inherited.Fingerprints) != 1 || posts != 1 {
		t.Fatalf("pending original observation lost: %+v posts=%d %v", inherited, posts, err)
	}
	empty, err := collector.Collect(ctx, request)
	if err != nil || len(empty.Fingerprints) != 0 || empty.ObservedAt != domain.Unix(now) || !strings.HasPrefix(empty.Provenance, "apple:") {
		t.Fatalf("newer empty Fleet receipt lost: %+v %v", empty, err)
	}
	empty, err = collector.Collect(ctx, request)
	if err != nil || len(empty.Fingerprints) != 0 || posts != 1 || count(t, admin, "work") != 1 || count(t, admin, "attempts") != 1 {
		t.Fatalf("inherited authority resurrected or manufactured attempts: %+v posts=%d %v", empty, posts, err)
	}
	// Equal observation times must preserve ListCollection's newest work order.
	// Seed the older durable receipt as fixture data; the current empty receipt
	// above still comes from a real authenticated Fleet request and result.
	olderReceipt, _ := json.Marshal(map[string]any{"observation": domain.CertificateObservation{DeviceID: "fleet:1", Fingerprints: []string{fp}, ObservedAt: domain.Unix(now), TrustVerified: true, Provenance: "apple:older:host", ExpiresAt: map[string]domain.Timestamp{fp: domain.Unix(now.Add(time.Hour))}}})
	if _, err = admin.pool.Exec(ctx, `INSERT INTO ledger.work(id,kind,payload,state,generation,receipt,created_at) SELECT id||':older',kind,payload,'succeeded',generation,$1,created_at-interval '1 hour' FROM ledger.work`, olderReceipt); err != nil {
		t.Fatal(err)
	}
	original.Hosts["host"].Observation.ObservedAt = inheritedNumber(now)
	inheritedRaw, _ := json.Marshal(original)
	if _, err = admin.pool.Exec(ctx, `UPDATE ledger.inherited_certificates SET document=$1`, inheritedRaw); err != nil {
		t.Fatal(err)
	}
	empty, err = collector.Collect(ctx, request)
	if err != nil || len(empty.Fingerprints) != 0 || empty.Provenance != "apple:"+command+":host" || posts != 1 {
		t.Fatalf("same-time older or inherited observation replaced newest real empty receipt: %+v posts=%d %v", empty, posts, err)
	}
}
