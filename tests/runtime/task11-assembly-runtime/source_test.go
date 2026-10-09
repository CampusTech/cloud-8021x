package main

import (
	"strings"
	"testing"
)

func TestSourceUnitsPreserveRealProcessesAndUnprivilegedPolicy(t *testing.T) {
	u := sourceUnits()
	for _, name := range []string{"step-ca", "step-ca-rsa"} {
		b := string(u["/etc/systemd/system/"+name+".service"])
		if !strings.Contains(b, "ExecStart=/usr/bin/step-ca /etc/"+name+"/config/ca.json") || strings.Contains(b, "cloud-8021x.service") {
			t.Fatal("source CA is not independently running real executable")
		}
	}
	policy := string(u["/etc/systemd/system/task11-source-policy.service"])
	if !strings.Contains(policy, "User=cloud8021x") || !strings.Contains(policy, "source-policy") {
		t.Fatal("source policy privilege differs")
	}
	native := string(u["/etc/systemd/system/freeradius.service.d/cloud-8021x.conf"])
	if !strings.Contains(native, "ExecStart=/usr/sbin/freeradius -d /etc/freeradius/3.0 -f") || strings.Contains(native, "cloud-8021x.service") {
		t.Fatal("native source identity differs")
	}
	if !strings.Contains(string(u["/etc/systemd/system/acme-authz-webhook.service"]), "/usr/local/bin/acme-authz-webhook serve") {
		t.Fatal("shipping compatibility webhook absent")
	}
}
func TestEnvironmentRejectsControlAndEscapesSystemdExpansion(t *testing.T) {
	if _, err := envLine("FLEET_API_TOKEN", []byte("bad\nvalue")); err == nil {
		t.Fatal("multiline value accepted")
	}
	got, err := envLine("FLEET_API_TOKEN", []byte("a\"\\$`%b"))
	if err != nil {
		t.Fatal(err)
	}
	if got != "FLEET_API_TOKEN=\"a\\\"\\\\\\$\\`%b\"\n" {
		t.Fatalf("unexpected environment quoting %q", got)
	}
}
