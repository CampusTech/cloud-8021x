package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type fleetHost struct {
	ID             int    `json:"id"`
	UUID           string `json:"uuid"`
	Platform       string `json:"platform"`
	OSVersion      string `json:"os_version"`
	TeamID         int    `json:"team_id"`
	MDMEnrolledAt  string `json:"last_mdm_enrolled_at"`
	EnrolledAt     string `json:"last_enrolled_at"`
	ScriptsEnabled bool   `json:"scripts_enabled,omitempty"`
	Serial         string `json:"hardware_serial,omitempty"`
	MDM            struct {
		Status   string `json:"enrollment_status"`
		Profiles []struct {
			UUID      string `json:"profile_uuid"`
			Status    string `json:"status"`
			Operation string `json:"operation_type"`
		} `json:"profiles"`
	} `json:"mdm"`
	Labels []struct {
		Name string `json:"name"`
	} `json:"labels"`
}
type fleetCommand struct {
	UUID        string `json:"command_uuid"`
	HostID      int    `json:"host_id"`
	HostUUID    string `json:"host_uuid"`
	CreatedAt   string `json:"created_at"`
	RequestType string `json:"request_type"`
	Mode        string `json:"mode,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
	ExecutionID string `json:"execution_id,omitempty"`
	Script      string `json:"script_contents,omitempty"`
	Command     string `json:"command,omitempty"`
	BodySHA256  string `json:"body_sha256,omitempty"`
	Posts       int    `json:"posts"`
}
type fleetSeed struct {
	Authorization string         `json:"authorization"`
	Hosts         []fleetHost    `json:"hosts"`
	Commands      []fleetCommand `json:"commands"`
}
type contractSeed struct {
	Peers             map[string]peerPolicy `json:"peers,omitempty"`
	Schema            int                   `json:"schema"`
	Gate              string                `json:"gate"`
	ApplicationSHA256 string                `json:"application_sha256"`
	Fleet             *fleetSeed            `json:"fleet,omitempty"`
	OTLP              *otlpSeed             `json:"otlp,omitempty"`
}

// Intake configuration is explicit; the endpoint remains a remote mock, not a
// shipping application transport override.
type otlpSeed struct {
	APIKey        string `json:"api_key,omitempty"`
	Host          string `json:"host"`
	Authorization string `json:"authorization"`
}

func (f *fixture) fleet(r *http.Request, body []byte) (int, any, string) {
	fail := func(code int, message string) (int, any, string) {
		return code, map[string]string{"error": message}, "application/json"
	}
	if f.config.Contract == nil || f.config.Contract.Fleet == nil {
		return fail(404, "Fleet fixture absent")
	}
	config := f.config.Contract.Fleet
	if config.Authorization == "" || r.Header.Get("Authorization") != config.Authorization {
		return fail(401, "Fleet authorization rejected")
	}
	if r.Method == "GET" && (r.URL.Path == "/api/v1/fleet/hosts" || strings.HasPrefix(r.URL.Path, "/api/v1/fleet/hosts/")) {
		if f.remote.InventoryError {
			return fail(503, "inventory unavailable")
		}
		if r.URL.Path != "/api/v1/fleet/hosts" {
			id, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/api/v1/fleet/hosts/"))
			if err != nil || r.URL.RawQuery != "" {
				return fail(404, "unknown host")
			}
			for _, h := range config.Hosts {
				if h.ID == id {
					return 200, map[string]any{"host": h}, "application/json"
				}
			}
			return fail(404, "unknown host")
		}
		q := r.URL.Query()
		page, e1 := strconv.Atoi(q.Get("page"))
		size, e2 := strconv.Atoi(q.Get("per_page"))
		if e1 != nil || e2 != nil || page < 0 || page > 10000 || size < 1 || size > 1000 || q.Get("device_mapping") != "true" {
			return fail(400, "invalid inventory page")
		}
		for k, v := range q {
			if len(v) != 1 || (k != "page" && k != "per_page" && k != "device_mapping" && k != "populate_labels") || (k == "populate_labels" && v[0] != "true") {
				return fail(400, "unlisted inventory query")
			}
		}
		rows := []fleetHost{}
		start := page * size
		for i := start; i < len(config.Hosts) && i < start+size; i++ {
			rows = append(rows, config.Hosts[i])
		}
		return 200, map[string]any{"hosts": rows}, "application/json"
	}
	if r.Method == "GET" && r.URL.Path == "/api/v1/fleet/commands/results" {
		q := r.URL.Query()
		if len(q) != 1 || len(q["command_uuid"]) != 1 {
			return fail(400, "unlisted command query")
		}
		c, ok := f.remote.Commands[q.Get("command_uuid")]
		if !ok || c.RequestType != "CertificateList" || c.Mode == "missing" {
			return fail(404, "command result absent")
		}
		result := "NotNow"
		if c.Mode == "terminal" {
			result = "Error"
		}
		return 200, map[string]any{"results": []map[string]string{{"host_uuid": c.HostUUID, "command_uuid": c.UUID, "request_type": "CertificateList", "status": result, "updated_at": c.UpdatedAt, "result": ""}}}, "application/json"
	}
	if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/v1/fleet/scripts/results/") && r.URL.RawQuery == "" {
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/fleet/scripts/results/")
		for _, c := range f.remote.Commands {
			if c.ExecutionID == id && c.RequestType == "Script" && c.Mode != "missing" {
				var exit *int
				if c.Mode == "terminal" {
					v := 1
					exit = &v
				}
				return 200, map[string]any{"host_id": c.HostID, "execution_id": c.ExecutionID, "script_contents": c.Script, "exit_code": exit, "created_at": c.CreatedAt, "output": ""}, "application/json"
			}
		}
		return fail(404, "script result absent")
	}
	if r.Method == "POST" && (r.URL.Path == "/api/v1/fleet/commands/run" || r.URL.Path == "/api/v1/fleet/scripts/run") && r.URL.RawQuery == "" {
		if f.phase != "active" {
			return fail(403, "passive Fleet submission denied")
		}
		c, err := f.decodeSubmission(r.URL.Path, body)
		if err != nil {
			return fail(400, err.Error())
		}
		if previous, ok := f.remote.Commands[c.UUID]; ok {
			previous.Posts++
			f.remote.Commands[c.UUID] = previous
			return fail(409, "duplicate command submission")
		}
		if len(f.remote.Commands) >= 128 {
			return fail(429, "command bound reached")
		}
		sum := sha256.Sum256(body)
		c.BodySHA256 = hex.EncodeToString(sum[:])
		c.Posts = 1
		c.Mode = "pending"
		c.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		c.UpdatedAt = c.CreatedAt
		f.remote.Commands[c.UUID] = c
		if f.remote.SubmissionUncertain {
			return 0, nil, "drop"
		}
		if c.RequestType == "Script" {
			return 200, map[string]any{"host_id": c.HostID, "execution_id": c.ExecutionID}, "application/json"
		}
		return 200, map[string]string{"command_uuid": c.UUID, "request_type": "CertificateList"}, "application/json"
	}
	return fail(404, "unlisted Fleet operation")
}

const applePrefix = `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CommandUUID</key><string>`
const appleSuffix = `</string><key>Command</key><dict><key>RequestType</key><string>CertificateList</string><key>ManagedOnly</key><true/></dict></dict></plist>`

var commandID = regexp.MustCompile(`^[A-Za-z0-9-]{1,253}$`)

func (f *fixture) decodeSubmission(path string, body []byte) (fleetCommand, error) {
	c := fleetCommand{}
	if strings.HasSuffix(path, "/commands/run") {
		var request struct {
			Command string   `json:"command"`
			Hosts   []string `json:"host_uuids"`
		}
		if strictJSON(body, &request) != nil || len(request.Hosts) != 1 {
			return c, errors.New("invalid exact command request")
		}
		raw, err := base64.StdEncoding.DecodeString(request.Command)
		if err != nil || len(raw) > 64<<10 || !strings.HasPrefix(string(raw), applePrefix) || !strings.HasSuffix(string(raw), appleSuffix) {
			return c, errors.New("unsupported CertificateList plist")
		}
		c.UUID = strings.TrimSuffix(strings.TrimPrefix(string(raw), applePrefix), appleSuffix)
		if !commandID.MatchString(c.UUID) {
			return c, errors.New("invalid command UUID")
		}
		c.HostUUID = request.Hosts[0]
		c.Command = request.Command
		c.RequestType = "CertificateList"
	} else {
		var request struct {
			HostID int    `json:"host_id"`
			Script string `json:"script_contents"`
		}
		if strictJSON(body, &request) != nil || request.HostID < 1 || len(request.Script) > 64<<10 {
			return c, errors.New("invalid script request")
		}
		base, nonce, ok := strings.Cut(request.Script, "\n# Collection nonce: ")
		if !ok || base == "" || !strings.HasSuffix(nonce, "\n") || !commandID.MatchString(strings.TrimSuffix(nonce, "\n")) {
			return c, errors.New("missing exact script nonce")
		}
		c.UUID = strings.TrimSuffix(nonce, "\n")
		c.HostID = request.HostID
		c.Script = request.Script
		c.RequestType = "Script"
		c.ExecutionID = "task11-execution-" + c.UUID
	}
	for _, host := range f.config.Contract.Fleet.Hosts {
		if (c.HostUUID == host.UUID && c.RequestType == "CertificateList" && host.Platform == "darwin") || (c.HostID == host.ID && c.RequestType == "Script" && host.Platform == "windows" && host.ScriptsEnabled) {
			c.HostID = host.ID
			c.HostUUID = host.UUID
			return c, nil
		}
	}
	return c, errors.New("submission host not in explicit fixture scope")
}
func (f *fixture) advanceScenario(name, command string) error {
	f.initializeRemote()
	if name != "fleet-pending" && name != "fleet-missing" && name != "fleet-terminal" && command != "" {
		return errors.New("scenario does not accept command identity")
	}
	switch name {
	case "fleet-pending", "fleet-missing", "fleet-terminal":
		c, ok := f.remote.Commands[command]
		if !ok {
			return errors.New("scenario command absent")
		}
		if c.Mode == "terminal" {
			return errors.New("terminal outcome immutable")
		}
		c.Mode = strings.TrimPrefix(name, "fleet-")
		if c.Mode == "terminal" {
			c.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		}
		f.remote.Commands[command] = c
	case "fleet-uncertain":
		f.remote.SubmissionUncertain = true
	case "inventory-error":
		f.remote.InventoryError = true
	case "inventory-ready":
		f.remote.InventoryError = false
	case "intake-unavailable":
		f.remote.IntakeUnavailable = true
	case "intake-ready":
		f.remote.IntakeUnavailable = false
	default:
		return errors.New("unlisted scenario")
	}
	return nil
}
