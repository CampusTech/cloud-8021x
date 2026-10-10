package main

import (
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

func TestSCEPClientMalformedKeyRefusesWithoutPanic(t *testing.T) {
	signer, key := pureClientCredential(t, "task11-scep-client")
	decrypter, _ := pureClientCredential(t, "pure recipient")
	for _, name := range []string{"private-modulus", "private-exponent", "private-primes", "decrypter-modulus"} {
		t.Run(name, func(t *testing.T) {
			badKey := *key
			badCert := *decrypter
			switch name {
			case "private-modulus":
				badKey.N = nil
			case "private-exponent":
				badKey.D = nil
			case "private-primes":
				badKey.Primes = nil
			case "decrypter-modulus":
				pub := *decrypter.PublicKey.(*rsa.PublicKey)
				pub.N = nil
				badCert.PublicKey = &pub
			}
			assertSCEPKeyRefusal(t, &badKey, signer, &badCert)
		})
	}
}
func assertSCEPKeyRefusal(t *testing.T, key *rsa.PrivateKey, signer, decrypter *x509.Certificate) {
	t.Helper()
	defer func() {
		if recover() != nil {
			t.Error("malformed private/client decrypter input panicked instead of refusing")
		}
	}()
	if _, e := makeSCEPRequest(key, signer, decrypter, "test-only-challenge", false); e == nil {
		t.Error("malformed SCEP key accepted")
	}
}
