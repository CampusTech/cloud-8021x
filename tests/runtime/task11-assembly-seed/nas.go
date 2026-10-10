package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// Called only after the closed unfinalized tree has been verified. Finalized
// trees and partial publication cannot repeat this generation.
func addNASInputs(files, values map[string][]byte) error {
	for _, name := range []string{"nas/scep-client.key", "nas/eap.conf", "nas/reject-eap.conf", "nas/radius-secret", "nas/broker-token"} {
		if _, exists := files[name]; exists {
			return errors.New("NAS material cannot be replaced")
		}
	}
	for _, name := range []string{"radius-task11-secret", "scep-broker-token"} {
		if len(values[name]) < 32 || len(values[name]) > 4096 {
			return errors.New("existing immutable synthetic credential required")
		}
	}
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		return errors.New("synthetic RSA client generation failed")
	}
	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return errors.New("synthetic client encoding failed")
	}
	defer clear(der)
	files["nas/scep-client.key"] = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	files["nas/radius-secret"] = bytes.Clone(values["radius-task11-secret"])
	files["nas/broker-token"] = bytes.Clone(values["scep-broker-token"])
	files["nas/eap.conf"] = []byte("network={\n ssid=\"task11\"\n key_mgmt=WPA-EAP\n eap=TLS\n identity=\"task11-native\"\n ca_cert=\"/var/lib/cloud8021x-task11-nas/ec-root.pem\"\n client_cert=\"/var/lib/cloud8021x-task11-nas/client.pem\"\n private_key=\"/var/lib/cloud8021x-task11-nas/client.key\"\n domain_suffix_match=\"radius.task11.test\"\n eapol_flags=0\n}\n")
	files["nas/reject-eap.conf"] = bytes.ReplaceAll(bytes.ReplaceAll(files["nas/eap.conf"], []byte("/client.pem"), []byte("/reject-client.pem")), []byte("/client.key"), []byte("/reject-client.key"))
	return nil
}
