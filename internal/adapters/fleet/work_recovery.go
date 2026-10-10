package fleet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/migration"
)

// RecoverCollectionWork reads only original scoped host/result resources. It
// releases no reservation itself and never turns terminal history into a fresh
// certificate observation. Candidate Windows execution IDs are untrusted hints.
func (c *Client) RecoverCollectionWork(ctx context.Context, payload, receipt json.RawMessage, hints []string) (LegacyRecoveryEvidence, error) {
	var r reservation
	var submitted collectionReceipt
	var empty LegacyRecoveryEvidence
	if c == nil || len(payload) > 1<<20 || domain.DecodeJSONStrict(payload, &r) != nil || r.HostID <= 0 || r.HostUUID == "" || r.UUID == "" || len(r.UUID) > 253 || r.CreatedAt <= 0 || len(r.Trust) != 64 || len(r.Key) != 64 || (r.Transport != "apple" && r.Transport != "windows") || len(hints) > 100 {
		return empty, errors.New("invalid original collection work")
	}
	if len(receipt) > 0 && string(receipt) != "null" && domain.DecodeJSONStrict(receipt, &submitted) != nil {
		return empty, errors.New("invalid original collection receipt")
	}
	var current struct {
		Host *host `json:"host"`
	}
	if e := c.request(ctx, "GET", "/api/v1/fleet/hosts/"+itoa(r.HostID), nil, &current); e != nil {
		return empty, e
	}
	if current.Host == nil || current.Host.ID != r.HostID || current.Host.UUID != r.HostUUID || current.Host.EnrolledAt != r.FleetEnrolledAt {
		return empty, errors.New("original collection host/enrollment differs")
	}
	h := current.Host
	enrollment := h.MDMEnrolledAt
	if r.Transport == "windows" {
		enrollment = h.EnrolledAt
		if h.Platform != "windows" {
			return empty, errors.New("original transport differs")
		}
	} else if !r.ManagedOnly || (h.Platform != "darwin" && h.Platform != "macos" && h.Platform != "ios" && h.Platform != "ipados") {
		return empty, errors.New("original Apple transport differs")
	}
	at, e := time.Parse(time.RFC3339Nano, enrollment)
	if e != nil || float64(domain.Unix(at)) != r.EnrolledAt {
		return empty, errors.New("original enrollment timestamp differs")
	}
	binding := fmt.Sprintf("%s\x00%d\x00%s\x00%s\x00%s\x00%s\x00%s", c.base, r.HostID, r.HostUUID, enrollment, r.FleetEnrolledAt, r.Trust, r.Transport)
	legacyHost := migration.LegacyCertificateHost{}
	id, _ := json.Marshal(r.HostID)
	legacyHost.Binding = []json.RawMessage{id, json.RawMessage(`null`), json.RawMessage(`null`)}
	command := migration.LegacyCommand{UUID: r.UUID, CreatedAt: json.Number(fmt.Sprintf("%.9f", r.CreatedAt)), Hosts: map[string][]json.RawMessage{r.HostUUID: legacyHost.Binding}}
	if r.Transport == "windows" {
		suffix := "\n# Collection nonce: " + r.UUID + "\n"
		if !strings.HasSuffix(r.Script, suffix) {
			return empty, errors.New("original script nonce differs")
		}
		hash := sha256.Sum256([]byte(strings.TrimSuffix(r.Script, suffix)))
		scriptHash := hex.EncodeToString(hash[:])
		binding += "\x00" + scriptHash
		encoded, _ := json.Marshal(scriptHash)
		legacyHost.Binding = append(legacyHost.Binding, encoded)
		command.Transport = "windows_script"
		command.ExecutionID = submitted.ExecutionID
		if r.ExecutionID != "" && command.ExecutionID != "" && r.ExecutionID != command.ExecutionID {
			return empty, errors.New("original execution differs")
		}
		if command.ExecutionID == "" {
			command.ExecutionID = r.ExecutionID
		}
	} else if len(hints) > 0 {
		return empty, errors.New("execution hints are Windows-only")
	}
	digest := sha256.Sum256([]byte(binding))
	if hex.EncodeToString(digest[:]) != r.Key || (r.LegacyScope != "" && r.LegacyScope != migration.LegacyCollectionScope(c.base, uint64(r.HostID), r.HostUUID)) {
		return empty, errors.New("original collection provider binding differs")
	}
	lowerBound, e := migration.ReceiptTime([]byte(command.CreatedAt))
	if e != nil {
		return empty, e
	}
	evidence := LegacyRecoveryEvidence{CommandUUID: r.UUID, HostUUID: r.HostUUID, HostID: uint64(r.HostID)}
	if command.Transport != "windows_script" || command.ExecutionID != "" {
		return c.recoverBoundCommand(ctx, r.HostUUID, legacyHost, command, "", lowerBound, evidence)
	}
	seen := map[string]bool{}
	var matched *LegacyRecoveryEvidence
	for _, hint := range hints {
		if hint == "" || len(hint) > 253 || seen[hint] {
			return empty, errors.New("invalid duplicate execution hint")
		}
		seen[hint] = true
		proof, e := c.recoverBoundCommand(ctx, r.HostUUID, legacyHost, command, hint, lowerBound, evidence)
		if e != nil {
			continue
		}
		if matched != nil {
			return empty, errors.New("ambiguous original execution evidence")
		}
		matched = &proof
	}
	if matched == nil {
		return empty, errors.New("original execution remains unknown")
	}
	return *matched, nil
}
