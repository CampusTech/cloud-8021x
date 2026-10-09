package migration

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"net/netip"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/network"
)

// NodeState retains original source times and raw snapshots. Files are retained
// in place, not translated into Datadog highwater or re-submitted as new events.
type NodeState struct {
	Version             int                        `json:"version"`
	Node                string                     `json:"node"`
	Inventory           json.RawMessage            `json:"inventory"`
	InventoryCache      json.RawMessage            `json:"inventory_cache,omitempty"`
	Metadata            json.RawMessage            `json:"metadata,omitempty"`
	Discovery           json.RawMessage            `json:"discovery,omitempty"`
	ProviderCaches      map[string]json.RawMessage `json:"provider_caches"`
	ProtectedSources    json.RawMessage            `json:"protected_sources,omitempty"`
	FingerprintEnforced bool                       `json:"fingerprint_enforced"`
	ClassKeySHA256      string                     `json:"class_key_sha256"`
	AuthFiles           []RetainedFile             `json:"auth_files"`
	AccountingFiles     []RetainedFile             `json:"accounting_files"`
}
type RetainedFile struct {
	Name, SHA256  string
	Device, Inode uint64
	Size          int64
	ModifiedAt    json.Number
}

func DecodeNodeState(raw []byte) (NodeState, error) {
	var n NodeState
	if len(raw) > 64<<20 || domain.DecodeJSONStrict(raw, &n) != nil || n.Version != 1 || (n.Node != "radius-primary" && n.Node != "radius-secondary") || !digestPattern.MatchString(n.ClassKeySHA256) {
		return n, errors.New("invalid current node export")
	}
	if _, e := domain.DecodeSnapshot(bytes.NewReader(n.Inventory)); e != nil {
		return n, e
	}
	if len(n.InventoryCache) > 0 {
		var c struct {
			Key   string
			Batch domain.DeviceSnapshot
		}
		if domain.DecodeJSONStrict(n.InventoryCache, &c) != nil || !digestPattern.MatchString(c.Key) || !c.Batch.Complete {
			return n, errors.New("invalid current inventory cache")
		}
		if _, e := domain.BuildSnapshot(c.Batch.Devices, c.Batch.ObservedAt); e != nil {
			return n, e
		}
	}
	if len(n.Metadata) > 0 {
		var d struct {
			Key       string
			Providers []domain.NetworkSnapshot
		}
		if domain.DecodeJSONStrict(n.Metadata, &d) != nil || !digestPattern.MatchString(d.Key) || len(d.Providers) > 64 {
			return n, errors.New("invalid current metadata")
		}
		for _, p := range d.Providers {
			if e := network.Validate(p); e != nil {
				return n, e
			}
		}
	}
	if len(n.Discovery) > 0 {
		var candidates []domain.SourceCandidate
		if domain.DecodeJSONStrict(n.Discovery, &candidates) != nil || len(candidates) > 4096 {
			return n, errors.New("invalid current discovery")
		}
		if e := validateRetainedCandidates(candidates); e != nil {
			return n, e
		}
	}
	if len(n.ProviderCaches) > 64 {
		return n, errors.New("provider export exceeds bound")
	}
	for key, raw := range n.ProviderCaches {
		var cache struct {
			Key   string
			Batch domain.NetworkSnapshot
		}
		if key == "" || len(key) > 253 || len(raw) > 16<<20 || domain.DecodeJSONStrict(raw, &cache) != nil || !digestPattern.MatchString(cache.Key) || cache.Batch.ProviderID != key || network.Validate(cache.Batch) != nil {
			return n, errors.New("invalid retained provider cache")
		}
	}
	if len(n.ProtectedSources) > 0 {
		var state struct {
			ConfigSHA256 string
			Candidates   []domain.SourceCandidate
		}
		if domain.DecodeJSONStrict(n.ProtectedSources, &state) != nil || !digestPattern.MatchString(state.ConfigSHA256) || validateRetainedCandidates(state.Candidates) != nil {
			return n, errors.New("invalid protected source state")
		}
	}
	for _, files := range [][]RetainedFile{n.AuthFiles, n.AccountingFiles} {
		if len(files) > 8192 {
			return n, errors.New("retained native file bound exceeded")
		}
		seen := map[string]bool{}
		for _, f := range files {
			if f.Name == "" || len(f.Name) > 253 || bytes.ContainsAny([]byte(f.Name), "/\\") || !digestPattern.MatchString(f.SHA256) || f.Size < 0 || f.Inode == 0 || seen[f.Name] {
				return n, errors.New("invalid retained native file")
			}
			if _, e := ReceiptTime([]byte(f.ModifiedAt)); e != nil {
				return n, e
			}
			seen[f.Name] = true
		}
	}
	return n, nil
}

// RollbackExport is a versioned cold-rollback archive, never an implicit resend
// instruction. New work stays in its original ledger schema beside compatible
// legacy files until exact terminal evidence permits a chosen recovery action.
type RollbackExport struct {
	Version             int                        `json:"version"`
	Transition          string                     `json:"transition"`
	Legacy              map[string]json.RawMessage `json:"legacy"`
	Current             map[string]json.RawMessage `json:"current"`
	Usage               json.RawMessage            `json:"usage,omitempty"`
	LegacyUsageRecovery string                     `json:"legacy_usage_recovery,omitempty"`
	UsageAbsent         bool                       `json:"usage_absent"`
	Ledger              LedgerExport               `json:"ledger"`
	Original            map[string]json.RawMessage `json:"original"`
	WorkersBlocked      bool                       `json:"workers_blocked"`
}
type LedgerExport struct {
	OperatorRecoveries       []json.RawMessage `json:"operator_recoveries"`
	OperatorRecoveryOutcomes []json.RawMessage `json:"operator_recovery_outcomes"`
	AuthQuarantine           []json.RawMessage `json:"auth_quarantine"`
	LegacyUsageFloor         []json.RawMessage `json:"legacy_usage_floor"`
	SchemaVersion            int               `json:"schema_version"`
	Work                     []json.RawMessage `json:"work"`
	Attempts                 []json.RawMessage `json:"attempts"`
	Reconciliations          []json.RawMessage `json:"reconciliations"`
	CollectionGuards         []json.RawMessage `json:"collection_guards"`
	Sessions                 []json.RawMessage `json:"sessions"`
	Intake                   []json.RawMessage `json:"intake"`
	Observations             []json.RawMessage `json:"observations"`
	Intervals                []json.RawMessage `json:"intervals"`
	Quarantine               []json.RawMessage `json:"quarantine"`
	AuthCursors              []json.RawMessage `json:"auth_cursors"`
}

func validateRetainedCandidates(candidates []domain.SourceCandidate) error {
	if len(candidates) > 4096 {
		return errors.New("source candidates exceed bound")
	}
	for _, c := range candidates {
		if c.ProviderID == "" || len(c.ProviderID) > 253 || c.SiteID == "" || len(c.SiteID) > 253 || c.ObservedAt <= 0 || math.IsInf(float64(c.ObservedAt), 0) || math.IsNaN(float64(c.ObservedAt)) || len(c.CIDRs) > 128 {
			return errors.New("invalid retained source identity")
		}
		for _, raw := range c.CIDRs {
			p, e := netip.ParsePrefix(raw)
			if e != nil || p != p.Masked() {
				return errors.New("invalid original source prefix")
			}
		}
	}
	return nil
}

// LegacyDevices projects only unambiguous current aliases with known metadata.
// Missing or ambiguous entries stay unavailable; the original snapshot lives in
// the export's original section, and current source time is never reset.
func LegacyDevices(raw []byte) (json.RawMessage, error) {
	snapshot, e := domain.DecodeSnapshot(bytes.NewReader(raw))
	if e != nil {
		return nil, e
	}
	type device struct {
		Email string           `json:"email"`
		Name  string           `json:"device_name"`
		Model string           `json:"device_model"`
		Time  domain.Timestamp `json:"ts"`
	}
	out := map[string]device{}
	for alias, record := range snapshot.Identities {
		if record == nil {
			continue
		}
		metadata := snapshot.Devices[record.DeviceID]
		if metadata == nil {
			continue
		}
		out[alias] = device{metadata.Owner, metadata.Name, metadata.Model, snapshot.UpdatedAt}
	}
	return json.Marshal(out)
}
