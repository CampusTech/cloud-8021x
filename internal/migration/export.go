package migration

import (
	"bytes"
	"encoding/json"
	"errors"
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
		for _, c := range candidates {
			if c.ProviderID == "" || c.SiteID == "" || c.ObservedAt <= 0 || len(c.CIDRs) > 128 {
				return n, errors.New("invalid current candidate")
			}
			for _, cidr := range c.CIDRs {
				if _, e := netip.ParsePrefix(cidr); e != nil {
					return n, e
				}
			}
		}
	}
	if len(n.ProviderCaches) > 64 {
		return n, errors.New("provider export exceeds bound")
	}
	for key, raw := range n.ProviderCaches {
		if key == "" || len(key) > 253 || len(raw) > 16<<20 || !json.Valid(raw) {
			return n, errors.New("invalid retained provider cache")
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
	Version        int                        `json:"version"`
	Transition     string                     `json:"transition"`
	Legacy         map[string]json.RawMessage `json:"legacy"`
	Current        map[string]json.RawMessage `json:"current"`
	Usage          json.RawMessage            `json:"usage,omitempty"`
	UsageAbsent    bool                       `json:"usage_absent"`
	Ledger         LedgerExport               `json:"ledger"`
	WorkersBlocked bool                       `json:"workers_blocked"`
}
type LedgerExport struct {
	AuthQuarantine   []json.RawMessage `json:"auth_quarantine"`
	SchemaVersion    int               `json:"schema_version"`
	Work             []json.RawMessage `json:"work"`
	Attempts         []json.RawMessage `json:"attempts"`
	Reconciliations  []json.RawMessage `json:"reconciliations"`
	CollectionGuards []json.RawMessage `json:"collection_guards"`
	Sessions         []json.RawMessage `json:"sessions"`
	Intake           []json.RawMessage `json:"intake"`
	Observations     []json.RawMessage `json:"observations"`
	Intervals        []json.RawMessage `json:"intervals"`
	Quarantine       []json.RawMessage `json:"quarantine"`
	AuthCursors      []json.RawMessage `json:"auth_cursors"`
}
