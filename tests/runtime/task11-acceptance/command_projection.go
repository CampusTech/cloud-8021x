package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/fleet"
	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/migration"
)

type durableGuard struct {
	ID, Source, HostUUID, State string
	Host                        migration.LegacyCertificateHost
	Command                     migration.LegacyCommand
	Evidence                    json.RawMessage
}
type collectionPayload struct {
	ManagedOnly     bool        `json:"managed_only"`
	Key             string      `json:"collection_key"`
	LegacyScope     string      `json:"legacy_scope,omitempty"`
	UUID            string      `json:"command_uuid"`
	HostID          int         `json:"host_id"`
	HostUUID        string      `json:"host_uuid"`
	EnrolledAt      json.Number `json:"enrolled_at"`
	FleetEnrolledAt string      `json:"fleet_enrolled_at"`
	CreatedAt       json.Number `json:"created_at"`
	Transport       string      `json:"transport"`
	ExecutionID     string      `json:"execution_id,omitempty"`
	Script          string      `json:"script,omitempty"`
	Trust           string      `json:"trust"`
}

func projectionHost(h migration.LegacyCertificateHost, c *commandExpectation) error {
	if len(h.Binding) < 3 || json.Unmarshal(h.Binding[0], &c.HostID) != nil || c.HostID < 1 {
		return errors.New("retained host binding unavailable")
	}
	mdm, err := migration.ReceiptTime(h.Binding[1])
	if err != nil {
		return err
	}
	if json.Unmarshal(h.Binding[2], &c.EnrolledAt) != nil {
		return errors.New("original enrollment unavailable")
	}
	c.Platform = h.Platform
	c.MDMEnrolledAt = mdm.UTC().Format(time.RFC3339Nano)
	return nil
}
func terminalCommand(raw []byte, c commandExpectation) bool {
	var proof fleet.LegacyRecoveryEvidence
	return domain.DecodeJSONStrict(raw, &proof) == nil && proof.Outcome == "terminal" && proof.HostID == uint64(c.HostID) && proof.HostUUID == c.HostUUID && proof.CommandUUID == c.UUID && len(proof.Response) > 2
}
func peerForOwner(owner string) (string, error) {
	switch owner {
	case "radius-primary":
		return "10.203.11.21", nil
	case "radius-secondary":
		return "10.203.11.22", nil
	}
	return "", errors.New("command owner not an enrolled green role")
}

// The exact production request serialization is derived from its retained claim,
// not from accepted remote request state. Unknown transports never get a guess.
func originalRequest(p collectionPayload) ([]byte, error) {
	if p.Transport == "windows" {
		if !strings.HasSuffix(p.Script, "\n# Collection nonce: "+p.UUID+"\n") {
			return nil, errors.New("original Windows nonce missing")
		}
		return json.Marshal(map[string]any{"host_id": p.HostID, "script_contents": p.Script})
	}
	if p.Transport != "apple" || !p.ManagedOnly || strings.ContainsAny(p.UUID, "<>&\"'") {
		return nil, errors.New("unsupported original collection request")
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CommandUUID</key><string>` + p.UUID + `</string><key>Command</key><dict><key>RequestType</key><string>CertificateList</string><key>ManagedOnly</key><true/></dict></dict></plist>`
	return json.Marshal(map[string]any{"command": base64.StdEncoding.EncodeToString([]byte(plist)), "host_uuids": []string{p.HostUUID}})
}
func projectCommands(s durableSnapshot, original migration.LegacyCertificateState, green map[string]migration.LegacyCertificateHost, phase string, terminal bool) ([]commandExpectation, error) {
	if phase != "active" && phase != "passive" {
		return nil, errors.New("exact recovery API phase required")
	}
	result := []commandExpectation{}
	seen := map[string]bool{}
	for _, g := range s.Guards {
		h, ok := original.Hosts[g.HostUUID]
		if !ok || !reflect.DeepEqual(h, g.Host) || g.Source != "https://fleet.task11.test" || !validSHA(g.ID) {
			return nil, errors.New("original private host differs from SQL import")
		}
		found := false
		for _, c := range original.Commands {
			if reflect.DeepEqual(c, g.Command) {
				found = true
			}
		}
		if !found || g.Command.Transport != "" {
			return nil, errors.New("original command request provenance unavailable")
		}
		c := commandExpectation{Origin: "retained-legacy", UUID: g.Command.UUID, HostUUID: g.HostUUID, Transport: "apple", RecoveryPeer: "10.203.11.21", RecoveryPhase: phase}
		if err := projectionHost(h, &c); err != nil {
			return nil, err
		}
		created, err := migration.ReceiptTime([]byte(g.Command.CreatedAt))
		if err != nil || created.After(s.Epoch) {
			return nil, errors.New("original command cannot postdate collection epoch")
		}
		c.OriginalCreatedAt = created.UTC().Format(time.RFC3339Nano)
		c.AcceptedBefore = c.OriginalCreatedAt
		if terminal && (g.State != "resolved" || !terminalCommand(g.Evidence, c)) {
			return nil, errors.New("original guard lacks matching terminal recovery")
		}
		if seen[c.UUID] {
			continue
		}
		seen[c.UUID] = true
		result = append(result, c)
	}
	for _, w := range s.Work {
		if !strings.HasPrefix(w.Kind, "fleet-cert:") {
			continue
		}
		if w.Generation < 1 || (w.State != "succeeded" && w.State != "quarantine" && w.State != "started") {
			return nil, errors.New("new command has no original attempt")
		}
		var p collectionPayload
		if domain.DecodeJSONStrict(w.Payload, &p) != nil || p.UUID == "" || len(p.UUID) > 253 || !validSHA(p.Key) || !validSHA(p.Trust) {
			return nil, errors.New("original claim invalid")
		}
		h, ok := green[p.HostUUID]
		if !ok {
			return nil, errors.New("host outside independently pinned remote enrollment")
		}
		c := commandExpectation{Origin: "green-work", UUID: p.UUID, HostUUID: p.HostUUID, Transport: p.Transport, Posts: 1, RequireUncertain: w.Outcome == "uncertain", RecoveryPeer: "10.203.11.21", RecoveryPhase: phase}
		if err := projectionHost(h, &c); err != nil {
			return nil, err
		}
		enrolled, e1 := migration.ReceiptTime([]byte(p.EnrolledAt))
		created, e2 := migration.ReceiptTime([]byte(p.CreatedAt))
		if e1 != nil || e2 != nil || p.HostID != c.HostID || p.FleetEnrolledAt != c.EnrolledAt || enrolled.UTC().Format(time.RFC3339Nano) != c.MDMEnrolledAt || created.Before(s.Epoch) || w.FinishedAt.Before(created) || w.FinishedAt.Sub(created) > 10*time.Minute {
			return nil, errors.New("original claim time/enrollment differs")
		}
		c.OriginalCreatedAt = created.UTC().Format(time.RFC3339Nano)
		c.AcceptedBefore = w.FinishedAt.UTC().Format(time.RFC3339Nano)
		var err error
		c.SubmissionPeer, err = peerForOwner(w.Owner)
		if err != nil {
			return nil, err
		}
		request, err := originalRequest(p)
		if err != nil {
			return nil, err
		}
		c.RequestSHA256 = adoption.Digest(request)
		if p.Transport == "windows" {
			c.ScriptSHA256 = adoption.Digest([]byte(p.Script))
		}
		if terminal && !terminalCommand(w.RecoveryEvidence, c) {
			return nil, errors.New("new command lacks actual terminal reconciliation")
		}
		if seen[c.UUID] {
			return nil, errors.New("duplicate command provenance")
		}
		seen[c.UUID] = true
		result = append(result, c)
	}
	if len(result) == 0 || len(result) > 128 {
		return nil, errors.New("bounded actual command evidence required")
	}
	return result, nil
}
