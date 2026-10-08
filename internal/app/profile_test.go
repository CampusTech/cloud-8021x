package app

import (
	"bytes"
	"encoding/json"
	"os/exec"
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
		t.Fatalf("legacy UUID mismatch: %s", x["PayloadUUID"])
	}
}

func TestRetainedPythonProfileFullParity(t *testing.T) {
	python, e := exec.LookPath("python3")
	if e != nil {
		t.Skip("retained development parity requires python3")
	}
	for _, identity := range []string{"device-uuid", "uuid-é-😀", "uuid-<>&"} {
		o := profileOptions{Identity: identity, Provisioner: "scep", SSID: "Campus", ServerDNS: "radius.example", SCEPURL: "https://ca.example/scep/scep"}
		input, _ := json.Marshal(map[string]string{"identity": identity, "provisioner": o.Provisioner, "ssid": o.SSID, "radius_server_name": o.ServerDNS, "scep_url": o.SCEPURL})
		cmd := exec.Command(python, "-c", `import runpy,sys,json,types
m=runpy.run_path('../../scripts/byod_profile.py')
a=types.SimpleNamespace(**json.load(sys.stdin))
sys.stdout.buffer.write(m['profile_bytes'](a,bytes([1,2,3]),'original-challenge'))`)
		cmd.Stdin = bytes.NewReader(input)
		old, e := cmd.Output()
		if e != nil {
			t.Fatal(e)
		}
		current, e := profileBytes(o, []byte{1, 2, 3}, "original-challenge")
		if e != nil {
			t.Fatal(e)
		}
		decode := func(data []byte) map[string]any {
			var result map[string]any
			if _, e := plist.Unmarshal(data, &result); e != nil {
				t.Fatal(e)
			}
			scep := result["PayloadContent"].([]any)[0].(map[string]any)["PayloadContent"].(map[string]any)
			subject := scep["Subject"].([]any)
			subject[1].([]any)[0].([]any)[1] = "<per-issuance-ou>"
			return result
		}
		if !reflect.DeepEqual(decode(old), decode(current)) {
			t.Fatalf("retained full profile differs for %q", identity)
		}
	}
}
