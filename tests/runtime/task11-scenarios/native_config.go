package main

import (
	"bytes"
	"crypto/x509"
	"errors"
	"net/http"
)

const nativeServerDNS = "radius.task11.test"

func fixedNASConfig() []byte {
	return []byte("network={\n ssid=\"task11\"\n key_mgmt=WPA-EAP\n eap=TLS\n identity=\"task11-native\"\n ca_cert=\"/var/lib/cloud8021x-task11-nas/ec-root.pem\"\n client_cert=\"/var/lib/cloud8021x-task11-nas/client.pem\"\n private_key=\"/var/lib/cloud8021x-task11-nas/client.key\"\n domain_suffix_match=\"" + nativeServerDNS + "\"\n eapol_flags=0\n}\n")
}
func validateNativeMaterials(p nasPrivatePlan, material map[string][]byte) error {
	config := material["eap.conf"]
	key := material["class-key"]
	if !bytes.Equal(config, fixedNASConfig()) || digestBytes(config) != p.Materials["eap.conf"] || len(key) < 32 || len(key) > 4096 || !bytes.Equal(key, bytes.Trim(key, " \t\n\r\v\f")) || digestBytes(key) != p.Materials["class-key"] {
		return errors.New("fixed independently pinned EAP/Class material required")
	}
	if _, e := fixedEAPArguments(p, material["radius-secret"]); e != nil {
		return e
	}
	client, e := pinnedECClient(p.EC, material["ec-root.pem"], material["ec-intermediate.pem"], material["client.pem"], material["client.key"])
	if e != nil {
		return e
	}
	defer client.CloseIdleConnections()
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || len(transport.TLSClientConfig.Certificates) != 1 {
		return errors.New("actual preserved EAP client unavailable")
	}
	pair := transport.TLSClientConfig.Certificates[0]
	if len(pair.Certificate) != 2 {
		return errors.New("actual EAP client chain unavailable")
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil || digestBytes(leaf.Raw) != p.ClientLeafSHA256 {
		return errors.New("actual EAP client differs from independent leaf pin")
	}
	return nil
}
