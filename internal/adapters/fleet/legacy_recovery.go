package fleet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/migration"
)

type LegacyRecoveryEvidence struct {
	CommandUUID string          `json:"command_uuid"`
	HostUUID    string          `json:"host_uuid"`
	HostID      uint64          `json:"host_id"`
	Outcome     string          `json:"outcome"`
	Response    json.RawMessage `json:"response"`
}

// RecoverLegacyCommand only reads the original fixed Fleet host/result resources.
// A result 404 can mean retention deletion; it never proves non-submission.
// Terminal evidence releases a reservation, never publishes certificate identity
// or replaces an original observation with the time of this poll.
func (c *Client) RecoverLegacyCommand(ctx context.Context, source, uuid string, h migration.LegacyCertificateHost, command migration.LegacyCommand, hint string) (LegacyRecoveryEvidence, error) {
	evidence := LegacyRecoveryEvidence{CommandUUID: command.UUID, HostUUID: uuid}
	if c == nil || c.base != source || len(h.Binding) < 3 || json.Unmarshal(h.Binding[0], &evidence.HostID) != nil || evidence.HostID == 0 || command.UUID == "" || len(command.UUID) > 253 {
		return evidence, errors.New("legacy recovery source/binding mismatch")
	}
	if _, ok := command.Hosts[uuid]; !ok {
		return evidence, errors.New("legacy recovery target absent")
	}
	var current struct {
		Host host `json:"host"`
	}
	if e := c.request(ctx, "GET", "/api/v1/fleet/hosts/"+strconv.FormatUint(evidence.HostID, 10), nil, &current); e != nil {
		return evidence, e
	}
	if uint64(current.Host.ID) != evidence.HostID || current.Host.UUID != uuid {
		return evidence, errors.New("legacy recovery current host differs")
	}
	enrollment := current.Host.MDMEnrolledAt
	if command.Transport == "windows_script" {
		enrollment = current.Host.EnrolledAt
		if current.Host.Platform != "windows" || h.Platform != "windows" {
			return evidence, errors.New("original Windows transport differs")
		}
	} else if command.Transport != "" || (current.Host.Platform != "darwin" && current.Host.Platform != "macos" && current.Host.Platform != "ios" && current.Host.Platform != "ipados") || current.Host.Platform != h.Platform {
		return evidence, errors.New("original Apple transport differs")
	}
	var retained float64
	var fleetEnrollment *string
	at, err := time.Parse(time.RFC3339Nano, enrollment)
	// Python datetime truncates parsed fractional timestamps to microseconds;
	// compare its original numeric representation without changing retained bytes.
	if err != nil || json.Unmarshal(h.Binding[1], &retained) != nil || retained <= 0 || float64(domain.Unix(at.Truncate(time.Microsecond))) != retained || json.Unmarshal(h.Binding[2], &fleetEnrollment) != nil || (fleetEnrollment == nil && current.Host.EnrolledAt != "") || (fleetEnrollment != nil && (*fleetEnrollment == "" || current.Host.EnrolledAt != *fleetEnrollment)) {
		return evidence, errors.New("original enrollment binding differs")
	}
	submitted, err := migration.ReceiptTime([]byte(command.CreatedAt))
	if err != nil {
		return evidence, err
	}
	// Fleet's legacy results are second precision. Only this lower bound is
	// floored; original request and response timestamps remain untouched.
	return c.recoverBoundCommand(ctx, uuid, h, command, hint, submitted.Truncate(time.Second), evidence)
}

// Both callers verify their own original enrollment representation before this
// shared GET-only terminal lookup; new work retains its exact timestamp bound.
func (c *Client) recoverBoundCommand(ctx context.Context, uuid string, h migration.LegacyCertificateHost, command migration.LegacyCommand, hint string, submitted time.Time, evidence LegacyRecoveryEvidence) (LegacyRecoveryEvidence, error) {
	if command.Transport == "windows_script" {
		execution := command.ExecutionID
		if execution == "" {
			execution = hint
		} else if hint != "" && hint != execution {
			return evidence, errors.New("original execution identity differs")
		}
		if execution == "" || len(execution) > 253 {
			return evidence, errors.New("unknown script requires bounded execution ID hint")
		}
		var row windowsResult
		e := c.request(ctx, "GET", "/api/v1/fleet/scripts/results/"+url.PathEscape(execution), nil, &row)

		if e != nil {
			return evidence, e
		}
		suffix := "\n# Collection nonce: " + command.UUID + "\n"
		if uint64(row.HostID) != evidence.HostID || row.ExecutionID != execution || row.ExitCode == nil || len(h.Binding) != 4 || !strings.HasSuffix(row.Script, suffix) {
			return evidence, errors.New("script not proven exact terminal original request")
		}
		var expected string
		if json.Unmarshal(h.Binding[3], &expected) != nil {
			return evidence, errors.New("original script digest missing")
		}
		sum := sha256.Sum256([]byte(strings.TrimSuffix(row.Script, suffix)))
		if hex.EncodeToString(sum[:]) != expected {
			return evidence, errors.New("script content differs from original")
		}
		raw, _ := json.Marshal(row.CreatedAt)
		created, e := migration.ReceiptTime(raw)
		if e != nil {
			return evidence, e
		}
		if created.Before(submitted) {
			return evidence, errors.New("script result predates original request")
		}
		evidence.Outcome = "terminal"
		evidence.Response, _ = json.Marshal(row)
		return evidence, nil
	}
	if hint != "" {
		return evidence, errors.New("execution hint is Windows-only")
	}
	var response struct {
		Results []appleResult `json:"results"`
	}
	e := c.request(ctx, "GET", "/api/v1/fleet/commands/results?"+url.Values{"command_uuid": {command.UUID}}.Encode(), nil, &response)

	if e != nil {
		return evidence, e
	}
	if response.Results == nil {
		return evidence, errors.New("missing original MDM result list")
	}
	var found *appleResult
	for i := range response.Results {
		r := &response.Results[i]
		if _, ok := command.Hosts[r.HostUUID]; !ok || r.CommandUUID != command.UUID || r.RequestType != "CertificateList" {
			return evidence, errors.New("MDM result escaped original target")
		}
		if r.HostUUID == uuid {
			if found != nil {
				return evidence, errors.New("ambiguous MDM result")
			}
			found = r
		}
	}
	if found == nil || (found.Status != "Acknowledged" && found.Status != "Error" && found.Status != "CommandFormatError") {
		return evidence, errors.New("original MDM request remains pending")
	}
	raw, _ := json.Marshal(found.UpdatedAt)
	at, e := migration.ReceiptTime(raw)
	if e != nil {
		return evidence, e
	}
	if at.Before(submitted) {
		return evidence, errors.New("MDM result predates original request")
	}
	evidence.Outcome = "terminal"
	evidence.Response, _ = json.Marshal(found)
	return evidence, nil
}
