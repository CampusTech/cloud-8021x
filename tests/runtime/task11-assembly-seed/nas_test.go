package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
)

func TestFinalizeAddsPinnedPersistentNASInputs(t *testing.T) {
	p, original := syntheticOriginal(t)
	b, e := finalize(p, original)
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"nas/scep-client.key", "nas/eap.conf", "nas/radius-secret", "nas/broker-token"} {
		if len(b.Original[name]) == 0 || b.Input.Files[name] != digest(b.Original[name]) {
			t.Fatalf("NAS input not finalized/pinned: %s", name)
		}
	}
	block, rest := pem.Decode(b.Original["nas/scep-client.key"])
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("persistent single PKCS8 key missing")
	}
	parsed, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(*rsa.PrivateKey)
	if e != nil || !ok || key.N.BitLen() < 2048 || key.Validate() != nil {
		t.Fatal("synthetic RSA client key missing")
	}
	var cloud cloudSeed
	if json.Unmarshal(b.Original["api/seed.json"], &cloud) != nil {
		t.Fatal("seed")
	}
	for file, secret := range map[string]string{"nas/radius-secret": "radius-task11-secret", "nas/broker-token": "scep-broker-token"} {
		value, e := base64.StdEncoding.DecodeString(cloud.Secrets["projects/111222333444/secrets/"+secret]["1"])
		if e != nil || !bytes.Equal(value, b.Original[file]) {
			t.Fatal("NAS credential differs from actual immutable secret")
		}
	}
	for _, name := range []string{"nas/client.pem", "nas/client.key", "source/run/radius-accounting-key", "source/etc/step-ca/config/ca.json"} {
		if !bytes.Equal(original[name], b.Original[name]) {
			t.Fatal("preserved original modified")
		}
	}
	if _, e = finalize(p, b.Original); e == nil {
		t.Fatal("finalized tree regenerated RSA key")
	}
}

func TestFinalizedRadiusSecretMatchesUnchangedNativeClientContract(t *testing.T) {
	p, files := syntheticOriginal(t)
	b, e := finalize(p, files)
	if e != nil {
		t.Fatal(e)
	}
	secret := b.Original["nas/radius-secret"]
	if !bytes.HasPrefix(secret, []byte("task11-")) || len(secret) > 253 {
		t.Fatal("actual finalized radius version1 cannot be passed to frozen native client")
	}
}
