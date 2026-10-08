package signaling

import (
	"context"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

func TestNumericHardwareParityAndValidation(t *testing.T) {
	a := domain.VLANAssignment{ID: 120, LocationID: "nyc"}
	ctx := domain.TrustedNetworkContext{LocationID: "nyc", Medium: domain.WiFi}
	for _, id := range []string{"unifi-numeric", "meraki-numeric"} {
		ctx.SignalingProfile = id
		s := StandardNumeric{}
		r, err := s.Encode(context.Background(), a, ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Attributes) != 3 || r.Attributes[0].Code != 64 || r.Attributes[0].Integer != 13 || r.Attributes[1].Code != 65 || r.Attributes[1].Integer != 6 || r.Attributes[2].Code != 81 || r.Attributes[2].String != "120" {
			t.Fatalf("wire %+v", r)
		}
		p := NumericProfile(id)
		if err := ValidateReply(p, a, ctx, r); err != nil {
			t.Fatal(err)
		}
		for _, attr := range []domain.NetworkAttribute{{Code: 25, Type: domain.StringValue, String: "forged class"}, {Code: 79, Type: domain.OctetsValue, Octets: []byte{1}}, {VendorID: 311, VendorType: 16, Type: domain.OctetsValue, Octets: []byte{1}}} {
			bad := r
			bad.Attributes = append(append([]domain.NetworkAttribute{}, r.Attributes...), attr)
			if ValidateReply(p, a, ctx, bad) == nil {
				t.Fatal("protected attribute")
			}
		}
		bad := r
		bad.Attributes[2].String = "0120"
		if ValidateReply(p, a, ctx, bad) == nil {
			t.Fatal("nondecimal VLAN")
		}
	}
}
func TestAlternateVendorCapabilityAndNoInventoryCoupling(t *testing.T) {
	a := domain.VLANAssignment{ID: 120, LocationID: "nyc"}
	ctx := domain.TrustedNetworkContext{LocationID: "nyc", Medium: domain.WiFi, SignalingProfile: "fake-vendor"}
	f := fakeNetwork{}
	var inventory domain.NetworkInventoryProvider = f
	_, _ = inventory.Fetch(context.Background(), domain.InventoryScope{ProviderID: "fake"})
	var signaler domain.VLANSignaler = f
	r, err := signaler.Encode(context.Background(), a, ctx)
	if err != nil {
		t.Fatal(err)
	}
	p := Profile{ID: "fake-vendor", Medium: domain.WiFi, Attributes: []AttributeRule{{VendorID: 12345, VendorType: 1, Type: domain.IntegerValue, Meaning: VLANInteger}}}
	if err := ValidateReply(p, a, ctx, r); err != nil {
		t.Fatal(err)
	}
	reg, err := NewRegistry([]Registration{{Profile: p, Signaler: signaler}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = reg.Encode(context.Background(), a, ctx); err != nil {
		t.Fatal(err)
	}
	ctx.SignalingProfile = "absent"
	if _, err = reg.Encode(context.Background(), a, ctx); err == nil {
		t.Fatal("missing capability")
	}
	ctx.SignalingProfile = p.ID
	ctx.Medium = domain.Wired
	if _, err = reg.Encode(context.Background(), a, ctx); err == nil {
		t.Fatal("wired signaled")
	}
	p.Attributes = append(p.Attributes, AttributeRule{Code: 25, Type: domain.StringValue})
	if _, err = NewRegistry([]Registration{{Profile: p, Signaler: f}}); err == nil {
		t.Fatal("protected profile")
	}
}

type fakeNetwork struct{}

func (fakeNetwork) Fetch(context.Context, domain.InventoryScope) (domain.NetworkSnapshot, error) {
	return domain.NetworkSnapshot{}, nil
}
func (fakeNetwork) Encode(_ context.Context, a domain.VLANAssignment, _ domain.TrustedNetworkContext) (domain.NetworkReply, error) {
	return domain.NetworkReply{Attributes: []domain.NetworkAttribute{{VendorID: 12345, VendorType: 1, Type: domain.IntegerValue, Integer: uint32(a.ID)}}}, nil
}
