package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func pureNASPlan() nasPrivatePlan {
	p := fixturePlan()
	materials := map[string]string{}
	for _, name := range nasMaterialNames {
		materials[name] = strings.Repeat("f", 64)
	}
	return nasPrivatePlan{Schema: 1, OriginalSeedSHA256: p.OriginalSeedSHA256, Scenario: p, Materials: materials, ClientLeafSHA256: strings.Repeat("a", 64), Station: "AA:BB:CC:DD:EE:FF", EC: ecClientPlan{Phase: "original", Peer: "10.203.11.31", DNS: "ec.task11.test", RootSHA256: materials["ec-root.pem"], IntermediateSHA256: materials["ec-intermediate.pem"], ClientCertificateSHA256: materials["client.pem"], ClientKeySHA256: materials["client.key"]}, RSA: caClientPlan{Blue: "10.203.11.31", DNS: "rsa.task11.test", Provisioner: "wifi-scep", RootSHA256: materials["rsa-root.pem"], IntermediateSHA256: materials["rsa-intermediate.pem"], DecrypterSHA256: materials["rsa-decrypter.pem"], BrokerCertificateSHA256: materials["broker.crt"], BrokerTLSName: "localhost", BrokerTokenSHA256: materials["broker-token"]}}
}
func TestNASPlanRequiresIndependentExactPinsAndClosedMaterials(t *testing.T) {
	p := pureNASPlan()
	raw, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := decodeNASPlan(raw, digestBytes(raw))
	if e != nil {
		t.Fatal(e)
	}
	if decoded.Materials["scep-client.key"] != p.Materials["scep-client.key"] || decoded.ClientLeafSHA256 != p.ClientLeafSHA256 {
		t.Fatal("independent client inputs lost")
	}
	for _, bad := range []string{"independent-pin", "missing", "extra", "path", "seed", "tls-pin", "duplicate", "unknown", "oversized"} {
		t.Run(bad, func(t *testing.T) {
			candidate := pureNASPlan()
			pin := digestBytes(raw)
			switch bad {
			case "missing":
				delete(candidate.Materials, "scep-client.key")
			case "extra":
				candidate.Materials["authority.key"] = strings.Repeat("f", 64)
			case "path":
				delete(candidate.Materials, "client.key")
				candidate.Materials["../client.key"] = strings.Repeat("f", 64)
			case "seed":
				candidate.OriginalSeedSHA256 = strings.Repeat("9", 64)
			case "tls-pin":
				candidate.EC.RootSHA256 = strings.Repeat("8", 64)
			}
			body, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			switch bad {
			case "duplicate":
				body = append([]byte(`{"schema":1,`), body[1:]...)
			case "unknown":
				body = append([]byte(`{"command":"id",`), body[1:]...)
			case "oversized":
				body = []byte(strings.Repeat(" ", 65537))
			case "independent-pin":
				pin = strings.Repeat("0", 64)
			}
			if bad != "independent-pin" {
				pin = digestBytes(body)
			}
			if _, err := decodeNASPlan(body, pin); err == nil {
				t.Fatal("unsafe/mutable NAS plan accepted")
			}
		})
	}
}
