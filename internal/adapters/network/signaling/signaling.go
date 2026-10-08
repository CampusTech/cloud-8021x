// Package signaling validates typed hardware capabilities independently of policy.
package signaling

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"unicode/utf8"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

type AttributeMeaning string

const (
	FixedInteger AttributeMeaning = "fixed-integer"
	VLANInteger  AttributeMeaning = "vlan-integer"
	VLANString   AttributeMeaning = "vlan-string"
)

type AttributeRule struct {
	Code       uint8
	VendorID   uint32
	VendorType uint8
	Type       domain.AttributeValueType
	Meaning    AttributeMeaning
	Fixed      uint32
	Tag        *uint8
}
type Profile struct {
	ID         string
	Medium     domain.NetworkMedium
	Attributes []AttributeRule
}
type StandardNumeric struct{}

func (StandardNumeric) Encode(ctx context.Context, a domain.VLANAssignment, n domain.TrustedNetworkContext) (domain.NetworkReply, error) {
	if err := ctx.Err(); err != nil {
		return domain.NetworkReply{}, err
	}
	if !domain.ValidVLAN(a.ID) || a.LocationID != n.LocationID || n.Medium != domain.WiFi {
		return domain.NetworkReply{}, errors.New("invalid VLAN or network context")
	}
	return domain.NetworkReply{Attributes: []domain.NetworkAttribute{{Code: 64, Type: domain.IntegerValue, Integer: 13}, {Code: 65, Type: domain.IntegerValue, Integer: 6}, {Code: 81, Type: domain.StringValue, String: strconv.Itoa(a.ID)}}}, nil
}
func NumericProfile(id string) Profile {
	return Profile{ID: id, Medium: domain.WiFi, Attributes: []AttributeRule{{Code: 64, Type: domain.IntegerValue, Meaning: FixedInteger, Fixed: 13}, {Code: 65, Type: domain.IntegerValue, Meaning: FixedInteger, Fixed: 6}, {Code: 81, Type: domain.StringValue, Meaning: VLANString}}}
}
func key(code uint8, vendor uint32, vtype uint8) string {
	return fmt.Sprintf("%d/%d/%d", code, vendor, vtype)
}

// Only standard VLAN tunnel attributes or explicitly registered non-protected vendor
// attributes can be returned. Policy identity/Class/EAP/MPPE/control state is never allowed.
func allowed(code uint8, vendor uint32, vtype uint8) bool {
	if vendor == 0 {
		return vtype == 0 && (code == 64 || code == 65 || code == 81)
	}
	if code != 0 || vtype == 0 {
		return false
	}
	if vendor == 311 {
		return false
	}
	return true
}
func tagEqual(a, b *uint8) bool { return (a == nil && b == nil) || (a != nil && b != nil && *a == *b) }
func validateProfile(p Profile) error {
	if p.ID == "" || p.Medium != domain.WiFi || len(p.Attributes) < 1 || len(p.Attributes) > 16 {
		return errors.New("invalid signaling profile")
	}
	seen := map[string]bool{}
	vlanFields := 0
	for _, r := range p.Attributes {
		k := key(r.Code, r.VendorID, r.VendorType)
		if !allowed(r.Code, r.VendorID, r.VendorType) || seen[k] || r.Tag != nil {
			return errors.New("protected, duplicate or tagged signaling attribute")
		}
		seen[k] = true
		switch r.Meaning {
		case FixedInteger:
			if r.Type != domain.IntegerValue {
				return errors.New("fixed attribute requires integer")
			}
		case VLANInteger:
			if r.Type != domain.IntegerValue {
				return errors.New("VLAN attribute requires integer")
			}
			vlanFields++
		case VLANString:
			if r.Type != domain.StringValue {
				return errors.New("VLAN attribute requires string")
			}
			vlanFields++
		default:
			return errors.New("unsupported signaling semantic")
		}
	}
	if vlanFields != 1 {
		return errors.New("missing or conflicting VLAN encoding")
	}
	if seen[key(64, 0, 0)] || seen[key(65, 0, 0)] || seen[key(81, 0, 0)] {
		if len(p.Attributes) != 3 || !seen[key(64, 0, 0)] || !seen[key(65, 0, 0)] || !seen[key(81, 0, 0)] {
			return errors.New("incomplete or conflicting standard tunnel encoding")
		}
		for _, r := range p.Attributes {
			if r.Code == 64 && (r.Meaning != FixedInteger || r.Fixed != 13) || r.Code == 65 && (r.Meaning != FixedInteger || r.Fixed != 6) || r.Code == 81 && r.Meaning != VLANString {
				return errors.New("invalid standard numeric profile")
			}
		}
	}
	return nil
}
func ValidateReply(p Profile, a domain.VLANAssignment, n domain.TrustedNetworkContext, reply domain.NetworkReply) error {
	if err := validateProfile(p); err != nil {
		return err
	}
	if !domain.ValidVLAN(a.ID) || a.LocationID != n.LocationID || p.ID != n.SignalingProfile || n.Medium != p.Medium || len(reply.Attributes) != len(p.Attributes) {
		return errors.New("signaling context, VLAN or attribute count mismatch")
	}
	rules := map[string]AttributeRule{}
	for _, r := range p.Attributes {
		rules[key(r.Code, r.VendorID, r.VendorType)] = r
	}
	seen := map[string]bool{}
	wireSize := 0
	for _, attr := range reply.Attributes {
		k := key(attr.Code, attr.VendorID, attr.VendorType)
		r, ok := rules[k]
		if !ok || seen[k] || !allowed(attr.Code, attr.VendorID, attr.VendorType) || attr.Type != r.Type || !tagEqual(attr.Tag, r.Tag) {
			return errors.New("protected, duplicate or unconfigured signaling attribute")
		}
		seen[k] = true
		size := 2
		switch attr.Type {
		case domain.IntegerValue:
			if attr.String != "" || len(attr.Octets) != 0 {
				return errors.New("mixed attribute value types")
			}
			want := r.Fixed
			if r.Meaning == VLANInteger {
				want = uint32(a.ID)
			}
			if attr.Integer != want {
				return errors.New("signaling integer does not match selected VLAN/profile")
			}
			size += 4
		case domain.StringValue:
			if attr.Integer != 0 || len(attr.Octets) != 0 || !utf8.ValidString(attr.String) || len(attr.String) > 253 || attr.String != strconv.Itoa(a.ID) {
				return errors.New("invalid or noncanonical numeric VLAN string")
			}
			size += len(attr.String)
		default:
			return errors.New("unsupported network attribute type")
		}
		if attr.VendorID != 0 {
			size += 6
		}
		if size > 255 {
			return errors.New("network attribute exceeds wire bound")
		}
		wireSize += size
	}
	if wireSize > 1024 {
		return errors.New("network reply exceeds wire bound")
	}
	return nil
}

type Registration struct {
	Profile  Profile
	Signaler domain.VLANSignaler
}
type Registry struct{ profiles map[string]Registration }

func NewRegistry(entries []Registration) (*Registry, error) {
	reg := &Registry{profiles: map[string]Registration{}}
	for _, entry := range entries {
		if err := validateProfile(entry.Profile); err != nil {
			return nil, err
		}
		if entry.Signaler == nil {
			return nil, errors.New("signaling capability missing")
		}
		if _, exists := reg.profiles[entry.Profile.ID]; exists {
			return nil, errors.New("duplicate signaling profile")
		}
		entry.Profile.Attributes = append([]AttributeRule(nil), entry.Profile.Attributes...)
		reg.profiles[entry.Profile.ID] = entry
	}
	return reg, nil
}
func Builtins() (*Registry, error) {
	return NewRegistry([]Registration{{Profile: NumericProfile("unifi-numeric"), Signaler: StandardNumeric{}}, {Profile: NumericProfile("meraki-numeric"), Signaler: StandardNumeric{}}})
}
func (r *Registry) Encode(ctx context.Context, a domain.VLANAssignment, n domain.TrustedNetworkContext) (domain.NetworkReply, error) {
	entry, ok := r.profiles[n.SignalingProfile]
	if !ok {
		return domain.NetworkReply{}, errors.New("configured signaling capability unavailable")
	}
	reply, err := entry.Signaler.Encode(ctx, a, n)
	if err != nil {
		return domain.NetworkReply{}, err
	}
	if err := ValidateReply(entry.Profile, a, n, reply); err != nil {
		return domain.NetworkReply{}, err
	}
	return reply, nil
}
