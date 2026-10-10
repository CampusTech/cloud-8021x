package app

import (
	"encoding/json"
	"os"
	"reflect"
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
		t.Fatalf("original UUID mismatch: %s", x["PayloadUUID"])
	}
}

// Goldens were decoded from the original Python generator before its retirement.
// Only the per-issuance OU is normalized; every other payload field is compared.
func TestOriginalProfileGoldenFullParity(t *testing.T) {
	for _, fixture := range []struct {
		name, identity, file string
	}{
		{"ASCII", "device-uuid", "byod-ascii.json"},
		{"Unicode", "uuid-é-😀", "byod-unicode.json"},
		{"HTML", "uuid-<>&", "byod-html.json"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			golden, err := os.ReadFile("testdata/" + fixture.file)
			if err != nil {
				t.Fatal(err)
			}
			var expected map[string]any
			if err := json.Unmarshal(golden, &expected); err != nil {
				t.Fatal(err)
			}
			o := profileOptions{Identity: fixture.identity, Provisioner: "scep", SSID: "Campus", ServerDNS: "radius.example", SCEPURL: "https://ca.example/scep/scep"}
			current, err := profileBytes(o, []byte{1, 2, 3}, "original-challenge")
			if err != nil {
				t.Fatal(err)
			}
			var decoded map[string]any
			if _, err := plist.Unmarshal(current, &decoded); err != nil {
				t.Fatal(err)
			}
			scep := decoded["PayloadContent"].([]any)[0].(map[string]any)["PayloadContent"].(map[string]any)
			subject := scep["Subject"].([]any)
			subject[1].([]any)[0].([]any)[1] = "<per-issuance-ou>"
			// JSON gives plist integers and certificate bytes the same representation
			// as the independent decoded golden (numbers and base64 respectively).
			normalized, err := json.Marshal(decoded)
			if err != nil {
				t.Fatal(err)
			}
			var actual map[string]any
			if err := json.Unmarshal(normalized, &actual); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(expected, actual) {
				t.Fatalf("full profile differs from original golden for %q", fixture.identity)
			}
		})
	}
}
