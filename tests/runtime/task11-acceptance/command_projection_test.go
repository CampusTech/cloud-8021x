package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/migration"
)

func TestCommandProjectionRetainsOriginalEnrollmentAndRefusesUnknownDelivery(t *testing.T) {
	at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	h := migration.LegacyCertificateHost{Platform: "darwin", Binding: []json.RawMessage{json.RawMessage(`1`), json.RawMessage(`1791547200`), json.RawMessage(`"2026-10-08T12:00:00Z"`)}}
	command := migration.LegacyCommand{UUID: "retained", CreatedAt: json.Number("1791547200"), Hosts: map[string][]json.RawMessage{syntheticDevice: h.Binding}}
	guard := durableGuard{ID: strings.Repeat("a", 64), Source: "https://fleet.task11.test", HostUUID: syntheticDevice, State: "resolved", Host: h, Command: command, Evidence: json.RawMessage(`{"command_uuid":"retained","host_uuid":"11111111-2222-4333-8444-555555555555","host_id":1,"outcome":"terminal","response":{"status":"Error"}}`)}
	original := migration.LegacyCertificateState{Hosts: map[string]migration.LegacyCertificateHost{syntheticDevice: h}, Commands: []migration.LegacyCommand{command}}
	s := durableSnapshot{Epoch: at.Add(time.Hour), Guards: []durableGuard{guard}}
	for name, change := range map[string]func(*durableGuard){"replacement": func(g *durableGuard) { g.Command.UUID = "replacement" }, "new-enrollment": func(g *durableGuard) {
		g.Host.Binding = append([]json.RawMessage{}, h.Binding...)
		g.Host.Binding[1] = json.RawMessage(`1791550800`)
	}, "unresolved": func(g *durableGuard) { g.State = "quarantine" }, "no-proof": func(g *durableGuard) { g.Evidence = nil }} {
		t.Run(name, func(t *testing.T) {
			v := s
			v.Guards = []durableGuard{guard}
			change(&v.Guards[0])
			if _, err := projectCommands(v, original, nil, "passive", true); err == nil {
				t.Fatal("retained command provenance changed")
			}
		})
	}
	got, err := projectCommands(s, original, nil, "passive", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Posts != 0 || got[0].OriginalCreatedAt != at.Format(time.RFC3339Nano) || got[0].AcceptedBefore != got[0].OriginalCreatedAt || got[0].RecoveryPeer != "10.203.11.21" {
		t.Fatalf("original command changed: %+v", got)
	}
}

func TestGreenWindowsEnrollmentIsIndependentOfOriginalSourceAuthority(t *testing.T) {
	at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	uuid := "22222222-3333-4444-8555-666666666666"
	h := migration.LegacyCertificateHost{Platform: "windows", Binding: []json.RawMessage{json.RawMessage(`2`), json.RawMessage(`1791460800`), json.RawMessage(`"2026-10-08T12:00:00Z"`)}}
	p := collectionPayload{UUID: "actual-green-command", HostID: 2, HostUUID: uuid, EnrolledAt: "1791460800", FleetEnrolledAt: "2026-10-08T12:00:00Z", CreatedAt: "1791547200", Transport: "windows", Script: "actual script\n# Collection nonce: actual-green-command\n", Key: strings.Repeat("a", 64), Trust: strings.Repeat("b", 64)}
	payload, _ := json.Marshal(p)
	s := durableSnapshot{Epoch: at, Work: []durableWork{{ID: "fleet-cert:actual", Kind: "fleet-cert:collection", State: "quarantine", Generation: 1, Owner: "radius-secondary", Payload: payload, Outcome: "uncertain", FinishedAt: at.Add(time.Second)}}}
	original := migration.LegacyCertificateState{Hosts: map[string]migration.LegacyCertificateHost{syntheticDevice: {Platform: "darwin"}}}
	green := map[string]migration.LegacyCertificateHost{uuid: h}
	got, err := projectCommands(s, original, green, "passive", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].HostID != 2 || got[0].ScriptSHA256 == "" || !got[0].RequireUncertain || got[0].SubmissionPeer != "10.203.11.22" {
		t.Fatal("actual Windows claim not preserved")
	}
	if len(original.Hosts) != 1 {
		t.Fatal("original source authority widened")
	}
	if _, err = projectCommands(s, original, nil, "passive", false); err == nil {
		t.Fatal("unapproved remote enrollment accepted")
	}
	p.FleetEnrolledAt = "2026-10-09T12:00:00Z"
	s.Work[0].Payload, _ = json.Marshal(p)
	if _, err = projectCommands(s, original, green, "passive", false); err == nil {
		t.Fatal("changed enrollment accepted")
	}
}
