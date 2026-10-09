package systemd

import (
	"strings"
	"testing"
)

func TestInstalledPrivilegeSeparation(t *testing.T) {
	units, e := Render()
	if e != nil {
		t.Fatal(e)
	}
	app := string(units["/etc/systemd/system/cloud-8021x.service"])
	for _, required := range []string{"Type=notify", "NotifyAccess=main", "Wants=network-online.target freeradius.service", "User=cloud8021x", "NoNewPrivileges=true", "CapabilityBoundingSet=\n", "Requires=cloud-8021x-credentials.service cloud-8021x-metadata.service", "ProtectSystem=strict"} {
		if !strings.Contains(app, required) {
			t.Fatalf("runtime lacks %s", required)
		}
	}
	native := string(units["/etc/systemd/system/freeradius.service.d/cloud-8021x.conf"])
	if !strings.Contains(native, "BindsTo=cloud-8021x.service") || !strings.Contains(native, "After=cloud-8021x-credentials.service cloud-8021x.service") {
		t.Fatal("native lifecycle is not bound to ready daemon")
	}
	sudo := string(units["/etc/sudoers.d/cloud-8021x"])
	if strings.Contains(sudo, "cloud8021x ALL") || !strings.Contains(sudo, "radius verify-leaf") || strings.Contains(sudo, "certificates renew") {
		t.Fatal("sudo widened beyond fixed freerad leaf hook")
	}
	for _, data := range units {
		if strings.Contains(string(data), "rm -") || strings.Contains(string(data), "logrotate") {
			t.Fatal("unconditional pending-log deletion")
		}
	}
}

func TestProtectedSourceTimerRetainsOneMinuteCadence(t *testing.T) {
	files, e := Render()
	if e != nil {
		t.Fatal(e)
	}
	timer := string(files["/etc/systemd/system/cloud-8021x-sources.timer"])
	if !strings.Contains(timer, "OnActiveSec=1min") || !strings.Contains(timer, "OnUnitActiveSec=1min") {
		t.Fatal("source cadence absent", timer)
	}
	if !strings.Contains(string(files["/etc/systemd/system/cloud-8021x-sources.service"]), "sources apply") {
		t.Fatal("timer bypasses protected command")
	}
}

// Vendor Trixie packages default to /etc/freeradius, while the protected Go
// renderer owns /etc/freeradius/3.0. Never start an unreviewed vendor-default tree.
func TestNativeServiceUsesProtectedConfigurationExplicitly(t *testing.T) {
	files, err := Render()
	if err != nil {
		t.Fatal(err)
	}
	native := string(files["/etc/systemd/system/freeradius.service.d/cloud-8021x.conf"])
	for _, command := range []string{
		"ExecStartPre=/usr/sbin/freeradius -d /etc/freeradius/3.0 -XC\n",
		"ExecStart=/usr/sbin/freeradius -d /etc/freeradius/3.0 -f\n",
	} {
		if !strings.Contains(native, command) {
			t.Fatalf("native service may load vendor default instead of protected configuration: missing %s", command)
		}
	}
}
