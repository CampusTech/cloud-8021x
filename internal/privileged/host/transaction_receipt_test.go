package host

import (
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

func TestNativeReceiptRejectsUnsupportedRetirementEvidence(t *testing.T) {
	const native = `{"native":{"mods-enabled/auth_detail":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"package_barrier":false,"was_running":false,"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","phase":"complete","had_radius":true,"tree_saved":true,"tree_swapped":true,"files":null}`
	var receipt Receipt
	if err := domain.DecodeJSONStrict([]byte(native), &receipt); err != nil {
		t.Fatal("ordinary native receipt rejected", err)
	}
	if receipt.Native["mods-enabled/auth_detail"] != strings.Repeat("a", 64) || receipt.Phase != "complete" || !receipt.HadRadius || !receipt.TreeSaved || !receipt.TreeSwapped {
		t.Fatal("ordinary native receipt lost independent attestation or rollback state")
	}
	for _, test := range []struct {
		name, evidence string
	}{
		{"null retirement", `"writer_retirement":null`},
		{"empty retirement", `"writer_retirement":{}`},
		{"completed retirement", `"writer_retirement":{"Transition":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","ReceiptSHA256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","Native":{"mods-enabled/auth_detail":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`},
		{"retirement manifest", `"radius_manifest_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := strings.TrimSuffix(native, "}") + "," + test.evidence + "}"
			var receipt Receipt
			if err := domain.DecodeJSONStrict([]byte(raw), &receipt); err == nil {
				t.Fatal("unsupported retirement evidence accepted alongside valid native attestation")
			}
		})
	}
}
