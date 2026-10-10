package freeradius

import (
	"strings"
	"testing"
)

func TestStaticNativeTemplatesFailClosed(t *testing.T) {
	o := fixtureOptions()
	files, e := Render(o)
	if e != nil {
		t.Fatal(e)
	}
	for _, check := range []struct{ file, text string }{{"mods-enabled/eap", "enable = no"}, {"mods-enabled/eap", "virtual_server = certificate-policy"}, {"mods-enabled/rest", "raw_value = yes"}, {"mods-enabled/rest", "start = 0"}, {"mods-enabled/sql", "start = 0"}, {"mods-enabled/sql", "INSERT INTO ledger.intake"}, {"sites-enabled/buffered", "track = yes"}, {"mods-enabled/auth_detail", "MS-MPPE-Send-Key"}, {"sites-enabled/default", "NAS-Port-Type[*]"}} {
		if !strings.Contains(string(files[check.file]), check.text) {
			t.Fatalf("%s missing %s", check.file, check.text)
		}
	}
	for _, data := range files {
		if strings.Contains(string(data), "python") || strings.Contains(string(data), "ON CONFLICT") {
			t.Fatal("runtime bypass")
		}
	}
	o.Host = "unsafe\ninclude"
	if _, e = Render(o); e == nil {
		t.Fatal("configuration injection")
	}
}
func fixtureOptions() Options {
	return Options{Host: "fixture", Generation: "0123456789abcdef", ConfigDir: "/etc/freeradius/3.0", AuthDirectory: "/var/log/cloud8021x-auth", SpoolDirectory: "/var/spool/cloud8021x-accounting", LeafDirectory: "/run/radius-verified-leaves", CertificateFile: "/run/certs/server.pem", KeyFile: "/run/certs/server.key", CAFile: "/run/certs/ca.pem", PolicyAddress: "127.0.0.1:18121", Bearer: strings.Repeat("a", 64), NativeConninfo: "host=localhost dbname=cloud8021x sslmode=verify-full sslrootcert=/run/certs/ca.pem", Clients: []Client{{ID: "office", Location: "nyc", CIDRs: []string{"127.0.0.1/32"}, Secret: "fixture-secret"}}}
}

func TestConfiguredStaticIPv6EnablesNativeListeners(t *testing.T) {
	o := fixtureOptions()
	o.Clients[0].CIDRs = append(o.Clients[0].CIDRs, "2001:db8::/64")
	files, e := Render(o)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Count(string(files["sites-enabled/default"]), "ipv6addr = ::") != 2 {
		t.Fatal("static IPv6 has no native auth/accounting listeners")
	}
}
