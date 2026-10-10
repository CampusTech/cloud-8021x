package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/migration"
)

func TestRejectClientCannotAlreadyExistInOriginalPolicyOrObservations(t *testing.T) {
	in := producerFixture(t)
	b, e := prepareNASBundle(in)
	if e != nil {
		t.Fatal(e)
	}
	p, e := decodeNASPlan(b.Plans["eap-unenrolled.json"], digestBytes(b.Plans["eap-unenrolled.json"]))
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := validateRejectClient(p.EC, b.Materials, p.RejectMaterials)
	if e != nil {
		t.Fatal(e)
	}
	for _, fault := range []string{"", "identity", "fingerprint", "hardware", "resolved-id", "host", "observation", "command", "malformed"} {
		t.Run(fault, func(t *testing.T) {
			policy, e := domain.DecodeSnapshot(bytes.NewReader(in.Files["source/etc/freeradius/3.0/device-policy-cache.json"]))
			if e != nil {
				t.Fatal(e)
			}
			state, e := migration.DecodeCertificates(in.Files["source/var/lib/cloud-8021x/certificate-state.json"])
			if e != nil {
				t.Fatal(e)
			}
			record := policy.Identities["11111111-2222-4333-8444-555555555555"]
			switch fault {
			case "identity":
				policy.Identities[rejectedDevice] = record
			case "fingerprint":
				policy.Certificates[digestBytes(leaf.Raw)] = record
			case "hardware":
				policy.HardwareSerials[rejectedDevice] = record
			case "resolved-id":
				record.DeviceID = domain.DeviceID(rejectedDevice)
			case "host":
				state.Hosts[rejectedDevice] = state.Hosts["11111111-2222-4333-8444-555555555555"]
			case "observation":
				h := state.Hosts["11111111-2222-4333-8444-555555555555"]
				h.Observation.Fingerprints = append(h.Observation.Fingerprints, digestBytes(leaf.Raw))
			case "command":
				h := state.Hosts["11111111-2222-4333-8444-555555555555"]
				state.Commands = []migration.LegacyCommand{{UUID: "task11-negative-must-refuse", CreatedAt: h.LastAttempt, Hosts: map[string][]json.RawMessage{rejectedDevice: h.Binding}}}
			}
			raw, _ := json.Marshal(state)
			if fault == "malformed" {
				raw = []byte("{}")
			}
			e = rejectClientAbsent(leaf, policy, raw)
			if fault == "" && e != nil {
				t.Fatal(e)
			}
			if fault != "" && e == nil {
				t.Fatal("existing identity accepted", fault)
			}
		})
	}
	for _, fault := range []string{"profile", "key", "root", "pin", "reuse"} {
		t.Run(fault, func(t *testing.T) {
			m := map[string][]byte{}
			for n, v := range b.Materials {
				m[n] = bytes.Clone(v)
			}
			pins := map[string]string{}
			for n, v := range p.RejectMaterials {
				pins[n] = v
			}
			switch fault {
			case "profile":
				m["reject-eap.conf"] = fixedNASConfig()
				pins["reject-eap.conf"] = digestBytes(m["reject-eap.conf"])
			case "key":
				m["reject-client.key"] = m["client.key"]
				pins["reject-client.key"] = digestBytes(m["reject-client.key"])
			case "root":
				m["ec-root.pem"] = m["rsa-root.pem"]
			case "pin":
				pins["reject-client.pem"] = strings.Repeat("0", 64)
			case "reuse":
				m["reject-client.pem"] = m["client.pem"]
				m["reject-client.key"] = m["client.key"]
				pins["reject-client.pem"] = digestBytes(m["reject-client.pem"])
				pins["reject-client.key"] = digestBytes(m["reject-client.key"])
			}
			if _, e := validateRejectClient(p.EC, m, pins); e == nil {
				t.Fatal("foreign/untrusted rejection material accepted")
			}
		})
	}
	block, _ := pem.Decode(b.Materials["client.pem"])
	positive, _ := x509.ParseCertificate(block.Bytes)
	if digestBytes(positive.Raw) == p.RejectLeafSHA256 || len(p.Materials) != 13 || len(p.RejectMaterials) != 3 || len(p.Scenario.Events) != 0 {
		t.Fatal("negative case changed enrolled positive identity/authority")
	}
	args, e := fixedEAPArguments(p, b.Materials["radius-secret"])
	if e != nil || args[1] != nasMaterialRoot+"/reject-eap.conf" {
		t.Fatal("negative native client profile not selected", e)
	}
	for _, raw := range b.Plans {
		q, e := decodeNASPlan(raw, digestBytes(raw))
		if e != nil {
			t.Fatal(e)
		}
		if q.Scenario.Case != "eap-unenrolled" && (len(q.Materials) != 13 || q.RejectMaterials != nil || q.RejectLeafSHA256 != "") {
			t.Fatal("positive immutable plan expanded")
		}
	}
}
