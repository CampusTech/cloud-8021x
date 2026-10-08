package app

import (
	"testing"

	"howett.net/plist"
)

func TestOptionalBYODProfileStableIdentityAndExactDeviceTarget(t *testing.T) {
	o := profileOptions{Identity: "device-uuid", Provisioner: "scep", SSID: "Campus", ServerDNS: "radius.example", SCEPURL: "https://ca.example/scep/scep"}
	a, e := profileBytes(o, []byte{1, 2, 3}, "private-challenge")
	if e != nil {
		t.Fatal(e)
	}
	b, e := profileBytes(o, []byte{1, 2, 3}, "new-challenge")
	if e != nil {
		t.Fatal(e)
	}
	var x, y map[string]any
	if _, e = plist.Unmarshal(a, &x); e != nil {
		t.Fatal(e)
	}
	if _, e = plist.Unmarshal(b, &y); e != nil {
		t.Fatal(e)
	}
	if x["PayloadUUID"] != y["PayloadUUID"] {
		t.Fatal("renewal changes stable profile identity")
	}
	content := x["PayloadContent"].([]any)
	scep := content[0].(map[string]any)["PayloadContent"].(map[string]any)
	if scep["Challenge"] != "private-challenge" || scep["KeyIsExtractable"] != false {
		t.Fatal("profile challenge/private-key contract changed")
	}
	wifi := content[2].(map[string]any)
	eap := wifi["EAPClientConfiguration"].(map[string]any)
	if eap["TLSAllowTrustExceptions"] != false {
		t.Fatal("trust exception enabled")
	}
	if x["PayloadUUID"] != "FDA6C11F-26D6-5B0B-AC54-14D31A13022B" {
		t.Fatalf("legacy UUID mismatch: %s", x["PayloadUUID"])
	}
}
