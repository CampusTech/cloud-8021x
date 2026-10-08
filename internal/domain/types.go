// Package domain contains provider-neutral inventory, policy and network contracts.
package domain

import (
	"context"
	"errors"
	"math"
	"time"
)

type DeviceID string
type GroupID string
type LocationID string
type Timestamp float64

func Unix(t time.Time) Timestamp { return Timestamp(float64(t.Unix()) + float64(t.Nanosecond())/1e9) }
func Fresh(observed Timestamp, now time.Time, maxAge time.Duration) bool {
	age := float64(Unix(now) - observed)
	return !math.IsNaN(age) && !math.IsInf(age, 0) && age >= 0 && maxAge > 0 && age < maxAge.Seconds()
}
func ValidVLAN(id int) bool { return id >= 1 && id <= 4094 }

type Device struct {
	ID             DeviceID
	Identities     []string
	HardwareSerial string
	Groups         []GroupID
	Enrolled       bool
	// Nil is an inventory without certificate collection. A pointer to [] means collection found none.
	Fingerprints           *[]string
	CertificatesObservedAt Timestamp
	Metadata               *DeviceMetadata
	MetadataPresent        bool
}
type DeviceMetadata struct {
	Serial string `json:"serial"`
	Name   string `json:"device_name"`
	Model  string `json:"device_model"`
	Owner  string `json:"device_owner"`
}
type InventoryScope struct {
	ProviderID string   `json:"provider_id"`
	IDs        []string `json:"ids"`
}
type DeviceSnapshot struct {
	Scope      InventoryScope
	Complete   bool
	ObservedAt Timestamp
	Devices    []Device
}
type DeviceInventoryProvider interface {
	Fetch(context.Context, InventoryScope) (DeviceSnapshot, error)
}

// Collection is an optional capability; inventory-only providers need not implement it.
type ManagedCertificateProvider interface {
	Collect(context.Context, CertificateCollectionRequest) (CertificateObservation, error)
}
type CertificateCollectionRequest struct {
	DeviceID  DeviceID
	RequestID string
}
type CertificateObservation struct {
	DeviceID      DeviceID
	Fingerprints  []string
	ObservedAt    Timestamp
	TrustVerified bool
	ExpiresAt     map[string]Timestamp
	Provenance    string
}

type CapabilityStatus string

const (
	CapabilityAvailable   CapabilityStatus = "available"
	CapabilityUnsupported CapabilityStatus = "unsupported"
	CapabilityFailed      CapabilityStatus = "failed"
)

type NetworkScopeResult struct {
	VLANStatus     CapabilityStatus
	VLANObservedAt Timestamp
	ScopeID        string
	Status         CapabilityStatus
	ObservedAt     Timestamp
}
type NetworkSnapshot struct {
	ProviderID     string
	Scope          InventoryScope
	Scopes         []NetworkScopeResult
	Sites          []NetworkSite
	Authenticators []Authenticator
	VLANs          []VLANMetadata
}
type NetworkSite struct {
	ID   string
	Name string
}
type Authenticator struct {
	ID          string
	SiteID      string
	HardwareMAC string
	// MACs are exact advertised aliases, scoped to this authenticator.
	MACs []string
	// InferredMACs are explicitly heuristic display aliases, lower priority than exact MACs.
	InferredMACs []string
	Name         string
	Ports        []string
}
type VLANMetadata struct {
	SiteID string
	ID     int
	Name   string
}
type SourceCandidate struct {
	ProviderID string
	SiteID     string
	CIDRs      []string
	ObservedAt Timestamp
}
type NetworkInventoryProvider interface {
	Fetch(context.Context, InventoryScope) (NetworkSnapshot, error)
}
type SourceDiscoveryProvider interface {
	DiscoverSources(context.Context, InventoryScope) ([]SourceCandidate, error)
}

type NetworkMedium string

const (
	WiFi  NetworkMedium = "wifi"
	Wired NetworkMedium = "wired"
)

// The local backend constructs this only from its authenticated client/source mapping.
// Packet-selected NAS identities and inventory metadata cannot select these fields.
type TrustedNetworkContext struct {
	ClientID         string
	LocationID       LocationID
	Medium           NetworkMedium
	SignalingProfile string
	SourceIP         string
}
type VLANAssignment struct {
	ID         int
	LocationID LocationID
}
type Decision struct {
	DeviceID    DeviceID
	Fingerprint string
	VLAN        *VLANAssignment
}
type AttributeValueType string

const (
	IntegerValue AttributeValueType = "uint32"
	StringValue  AttributeValueType = "string"
	OctetsValue  AttributeValueType = "octets"
)

// Exactly one value field is used. Standard Code and vendor identity are mutually exclusive.
type NetworkAttribute struct {
	Code       uint8
	VendorID   uint32
	VendorType uint8
	Type       AttributeValueType
	Tag        *uint8
	Integer    uint32
	String     string
	Octets     []byte
}
type NetworkReply struct{ Attributes []NetworkAttribute }
type VLANSignaler interface {
	Encode(context.Context, VLANAssignment, TrustedNetworkContext) (NetworkReply, error)
}

var ErrIncompleteSnapshot = errors.New("inventory refresh is incomplete")
