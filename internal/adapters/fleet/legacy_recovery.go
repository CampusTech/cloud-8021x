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
		if errors.Is(e, errNotFound) && command.ExecutionID != "" {
			evidence.Outcome = "absent"
			evidence.Response = json.RawMessage(`{"status":404}`)
			return evidence, nil
		}
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
		submitted, e := migration.ReceiptTime([]byte(command.CreatedAt))
		if e != nil || created.Before(submitted) {
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
	if errors.Is(e, errNotFound) {
		evidence.Outcome = "absent"
		evidence.Response = json.RawMessage(`{"status":404}`)
		return evidence, nil
	}
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
	submitted, e := migration.ReceiptTime([]byte(command.CreatedAt))
	if e != nil || at.Before(submitted) {
		return evidence, errors.New("MDM result predates original request")
	}
	evidence.Outcome = "terminal"
	evidence.Response, _ = json.Marshal(found)
	return evidence, nil
}
