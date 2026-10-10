package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

var originalNames = []string{"spec.json", "api/seed.json", "source/etc/step-ca/certs/root_ca.crt", "source/etc/step-ca/certs/intermediate_ca.crt", "source/etc/step-ca/config/ca.json", "source/etc/step-ca/templates/x509/wifi-acme.tpl", "source/etc/step-ca-rsa/certs/root_ca.crt", "source/etc/step-ca-rsa/certs/intermediate_ca.crt", "source/etc/step-ca-rsa/config/ca.json", "source/etc/step-ca-rsa/templates/x509/wifi-scep.tpl", "source/etc/acme-authz-webhook/server.crt", "source/etc/acme-authz-webhook/server.key", "source/etc/freeradius/3.0/certs/server.pem", "source/etc/freeradius/3.0/certs/server-key.pem", "source/etc/freeradius/3.0/certs/ca.pem", "source/etc/freeradius/3.0/device-policy-cache.json", "source/var/lib/cloud-8021x/certificate-state.json", "source/etc/cloud8021x-task11-source-provenance.json", "source/var/lib/cloud-8021x/fingerprint-enforced", "source/run/radius-accounting-key"}
var inheritedSecrets = []string{"smallstep-ca-cert", "smallstep-intermediate-cert", "smallstep-scep-decrypter-cert", "smallstep-scep-decrypter-key", "smallstep-rsa-root-cert", "smallstep-rsa-intermediate-cert", "smallstep-rsa-scep-decrypter-cert", "smallstep-rsa-scep-decrypter-key", "radius-smallstep-server-cert", "radius-smallstep-server-key", "radius-accounting-class-key"}

func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func originalManifest(files map[string][]byte) ([]byte, error) {
	m := struct {
		Schema int
		Files  map[string]string
	}{1, map[string]string{}}
	for _, p := range originalNames {
		if len(files[p]) == 0 {
			return nil, errors.New("original input absent")
		}
		m.Files[p] = digest(files[p])
	}
	return json.Marshal(m)
}

func originalTreeNames() []string {
	return append(append([]string{}, originalNames...), "original-manifest.json", "api/ec-kms.pem", "api/rsa-kms.pem", "private-original/ec-root.pem", "private-original/rsa-root.pem", "nas/client.pem", "nas/client.key", "nas/reject-client.pem", "nas/reject-client.key")
}
func validateOriginalTree(files map[string][]byte) error {
	names := originalTreeNames()
	if len(files) != len(names) {
		return errors.New("exact unfinalized controller tree required")
	}
	for _, name := range names {
		if len(files[name]) == 0 {
			return errors.New("original private input missing")
		}
	}
	return nil
}
