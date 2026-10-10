package host

import "testing"

func TestInstalledFileAllowlistRejectsArbitraryRootWrites(t *testing.T) {
	for _, p := range []string{"/etc/cloud-8021x/sources/other.conf", "/etc/sudoers", "/etc/cloud-8021x/../../etc/sudoers", "/etc/systemd/system/sshd.service", "/etc/freeradius/3.0/unreviewed"} {
		if AllowedFile(p) {
			t.Fatalf("arbitrary path %s", p)
		}
	}
	for _, p := range []string{"/etc/cloud-8021x/sources/clients.conf", "/etc/cloud-8021x/metadata.nft", "/etc/step-ca/config/ca.json", "/etc/freeradius/3.0/mods-enabled/eap"} {
		if !AllowedFile(p) {
			t.Fatalf("fixed path %s", p)
		}
	}
}
