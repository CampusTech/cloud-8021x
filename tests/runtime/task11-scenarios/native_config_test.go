package main

import (
	"bytes"
	"testing"
)

func TestFixedNativeConfigurationCannotInjectPathsOrHooks(t *testing.T) {
	want := []byte("network={\n ssid=\"task11\"\n key_mgmt=WPA-EAP\n eap=TLS\n identity=\"task11-native\"\n ca_cert=\"/var/lib/cloud8021x-task11-nas/ec-root.pem\"\n client_cert=\"/var/lib/cloud8021x-task11-nas/client.pem\"\n private_key=\"/var/lib/cloud8021x-task11-nas/client.key\"\n domain_suffix_match=\"radius.task11.test\"\n eapol_flags=0\n}\n")
	if !bytes.Equal(fixedNASConfig(), want) {
		t.Fatal("native config lacks closed preserved client/trust paths")
	}
}
func TestNativeMaterialValidationUsesActualIndependentCertificateIdentity(t *testing.T) {
	input, material, chain := pureECExecutionInput(t)
	p := input.Plan
	p.ClientLeafSHA256 = digestBytes(chain.old.Raw)
	material["eap.conf"] = fixedNASConfig()
	p.Materials["eap.conf"] = digestBytes(material["eap.conf"])
	material["radius-secret"] = []byte("task11-private-nas-secret")
	p.Materials["radius-secret"] = digestBytes(material["radius-secret"])
	material["class-key"] = bytes.Repeat([]byte("k"), 32)
	p.Materials["class-key"] = digestBytes(material["class-key"])
	// Other CA files are irrelevant to EAP; full loader pins all13 separately.
	if e := validateNativeMaterials(p, material); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{"config", "leaf", "root", "key", "secret", "class"} {
		t.Run(bad, func(t *testing.T) {
			altered := map[string][]byte{}
			for k, v := range material {
				altered[k] = bytes.Clone(v)
			}
			plan := p
			plan.Materials = map[string]string{}
			for k, v := range p.Materials {
				plan.Materials[k] = v
			}
			switch bad {
			case "config":
				altered["eap.conf"] = append(altered["eap.conf"], []byte("ctrl_interface=/outside\n")...)
				plan.Materials["eap.conf"] = digestBytes(altered["eap.conf"])
			case "leaf":
				plan.ClientLeafSHA256 = digestBytes([]byte("foreign-leaf"))
			case "root":
				altered["ec-root.pem"] = []byte("foreign-root")
			case "key":
				altered["client.key"] = []byte("foreign-key")
			case "secret":
				altered["radius-secret"] = []byte("not-synthetic")
				plan.Materials["radius-secret"] = digestBytes(altered["radius-secret"])
			case "class":
				altered["class-key"] = nil
				plan.Materials["class-key"] = digestBytes(nil)
			}
			if validateNativeMaterials(plan, altered) == nil {
				t.Fatal("unsafe native material admitted")
			}
		})
	}
}
