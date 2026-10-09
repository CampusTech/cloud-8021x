package freeradius

import (
	"strings"
	"testing"
)

func TestFinalAuthCertificateObservationUsesServerTLSContext(t *testing.T) {
	files, err := Render(fixtureOptions())
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"Expiration", "Issuer"} {
		if !strings.Contains(string(files["sites-enabled/default"]), "C8021X-Cert-"+field+" := \"%{request:TLS-Client-Cert-"+field+"}\"") {
			t.Error("completed TLS monitoring field missing", field)
		}
		if !strings.Contains(string(files["mods-enabled/auth_detail"]), "TLS-Client-Cert-"+field) {
			t.Error("original TLS privacy suppression removed")
		}
	}
}
