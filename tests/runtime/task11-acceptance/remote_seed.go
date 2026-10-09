package main

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/migration"
)

const syntheticWindows = "22222222-3333-4444-8555-666666666666"

type remoteSeedSpec struct{ ApplicationSHA256, FleetAuthorization, IntakeHost, IntakeAPIKey string }
type remoteHost struct {
	ID             int             `json:"id"`
	UUID           string          `json:"uuid"`
	Platform       string          `json:"platform"`
	OSVersion      string          `json:"os_version"`
	TeamID         int             `json:"team_id"`
	MDMEnrolledAt  string          `json:"last_mdm_enrolled_at"`
	EnrolledAt     string          `json:"last_enrolled_at"`
	ScriptsEnabled bool            `json:"scripts_enabled,omitempty"`
	Serial         string          `json:"hardware_serial,omitempty"`
	MDM            json.RawMessage `json:"mdm"`
	Labels         json.RawMessage `json:"labels"`
}
type remoteFleet struct {
	Authorization string            `json:"authorization"`
	Hosts         []remoteHost      `json:"hosts"`
	Commands      []json.RawMessage `json:"commands"`
}
type remoteContract struct {
	Schema            int                          `json:"schema"`
	Gate              string                       `json:"gate"`
	ApplicationSHA256 string                       `json:"application_sha256"`
	Peers             map[string]map[string]string `json:"peers"`
	Fleet             remoteFleet                  `json:"fleet"`
	OTLP              map[string]string            `json:"otlp"`
}

func makeRemoteContract(s remoteSeedSpec, at time.Time) (*remoteContract, error) {
	if !validSHA(s.ApplicationSHA256) || !strings.HasPrefix(s.FleetAuthorization, "Bearer ") || len(s.FleetAuthorization) < 16 || len(s.IntakeAPIKey) < 16 || strings.ContainsAny(s.FleetAuthorization+s.IntakeAPIKey, "\r\n") {
		return nil, errors.New("explicit synthetic remote credentials and application pin required")
	}
	allowed := false
	for _, site := range []string{"datadoghq.com", "us3.datadoghq.com", "us5.datadoghq.com", "datadoghq.eu", "ap1.datadoghq.com", "ap2.datadoghq.com"} {
		allowed = allowed || s.IntakeHost == "otlp."+site
	}
	if !allowed {
		return nil, errors.New("exact shipping business intake host required")
	}
	c := &remoteContract{Schema: 1, Gate: "installed-traffic", ApplicationSHA256: s.ApplicationSHA256, Peers: map[string]map[string]string{}, Fleet: remoteFleet{Authorization: s.FleetAuthorization}, OTLP: map[string]string{"host": s.IntakeHost, "api_key": s.IntakeAPIKey, "authorization": ""}}
	for ip, role := range map[string]string{"10.203.11.31": "original-primary", "10.203.11.32": "original-secondary", "10.203.11.21": "green-primary", "10.203.11.22": "green-secondary"} {
		phase := "passive"
		if strings.HasPrefix(role, "original-") {
			phase = "active"
		}
		c.Peers[ip] = map[string]string{"role": role, "phase": phase}
	}
	enrolled := at.Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	c.Fleet.Hosts = []remoteHost{{ID: 1, UUID: syntheticDevice, Platform: "darwin", OSVersion: "15.0", TeamID: 1, MDMEnrolledAt: at.UTC().Format(time.RFC3339), EnrolledAt: enrolled, MDM: json.RawMessage(`{"enrollment_status":"On","profiles":[]}`), Labels: json.RawMessage(`[]`)}, {ID: 2, UUID: syntheticWindows, Platform: "windows", OSVersion: "11", TeamID: 1, MDMEnrolledAt: enrolled, EnrolledAt: enrolled, ScriptsEnabled: true, MDM: json.RawMessage(`{"enrollment_status":"On","profiles":[]}`), Labels: json.RawMessage(`[]`)}}
	command, err := json.Marshal(map[string]any{"command_uuid": "task11-retained-command-0001", "host_id": 1, "host_uuid": syntheticDevice, "created_at": at.UTC().Format(time.RFC3339), "request_type": "CertificateList", "posts": 0})
	if err != nil {
		return nil, err
	}
	c.Fleet.Commands = []json.RawMessage{command}
	return c, nil
}

// This projection reads the independently pinned immutable seed, never mutable
// intake or remote result state. It grants no original-source authorization.
func approvedGreenHosts(raw []byte, app string) (map[string]migration.LegacyCertificateHost, error) {
	var top map[string]json.RawMessage
	if err := decodeExactJSON(raw, &top); err != nil {
		return nil, err
	}
	var c remoteContract
	if decodeExactJSON(top["contract"], &c) != nil || c.Schema != 1 || c.Gate != "installed-traffic" || c.ApplicationSHA256 != app || len(c.Fleet.Hosts) != 2 {
		return nil, errors.New("reviewed installed API enrollment required")
	}
	h := c.Fleet.Hosts[1]
	if c.Fleet.Hosts[0].ID != 1 || c.Fleet.Hosts[0].UUID != syntheticDevice || h.ID != 2 || h.UUID != syntheticWindows || h.Platform != "windows" || !h.ScriptsEnabled || h.Serial != "" {
		return nil, errors.New("remote host scope changed")
	}
	mdm, err := time.Parse(time.RFC3339Nano, h.MDMEnrolledAt)
	if err != nil {
		return nil, err
	}
	enrolled, err := time.Parse(time.RFC3339Nano, h.EnrolledAt)
	if err != nil || !enrolled.Equal(mdm) || mdm.Nanosecond() != 0 {
		return nil, errors.New("approved Windows enrollment unavailable")
	}
	stamp, _ := json.Marshal(h.EnrolledAt)
	return map[string]migration.LegacyCertificateHost{h.UUID: {Platform: h.Platform, Binding: []json.RawMessage{json.RawMessage(`2`), json.RawMessage(strconv.FormatInt(mdm.Unix(), 10)), stamp}}}, nil
}
