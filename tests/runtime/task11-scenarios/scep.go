package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"strings"

	"github.com/smallstep/scep"
	"github.com/smallstep/scep/x509util"
)

// makeSCEPRequest is a client only. A live caller must use the real broker's
// protected bounded challenge, original decrypter, and actual issued renewal
// signer. No installation receipt, challenge, authority or server is created.
func makeSCEPRequest(key *rsa.PrivateKey, signer, decrypter *x509.Certificate, challenge string, renewal bool) (*scep.PKIMessage, error) {
	if key == nil || key.N == nil || key.D == nil || len(key.Primes) < 2 || key.N.BitLen() < 2048 || key.D.Sign() <= 0 || key.Validate() != nil || signer == nil || decrypter == nil || challenge == "" || len(challenge) > 4096 || strings.ContainsAny(challenge, "\r\n\x00") {
		return nil, errors.New("bounded genuine SCEP client inputs required")
	}
	actual, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	expected, err := x509.MarshalPKIXPublicKey(signer.PublicKey)
	if err != nil || !bytes.Equal(actual, expected) {
		return nil, errors.New("SCEP signer/key identity mismatch")
	}
	recipient, ok := decrypter.PublicKey.(*rsa.PublicKey)
	if !ok || recipient == nil || recipient.N == nil || recipient.N.BitLen() < 2048 || recipient.E < 3 || recipient.E%2 == 0 || decrypter.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		return nil, errors.New("original RSA decrypter required")
	}
	der, err := x509util.CreateCertificateRequest(rand.Reader, &x509util.CertificateRequest{CertificateRequest: x509.CertificateRequest{Subject: pkix.Name{CommonName: "task11-scep-client", OrganizationalUnit: []string{"task11-renewal-continuity"}}}, ChallengePassword: challenge}, key)
	if err != nil {
		return nil, errors.New("SCEP CSR creation failed")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil {
		return nil, errors.New("SCEP CSR signature invalid")
	}
	kind := scep.PKCSReq
	if renewal {
		kind = scep.RenewalReq
	}
	return scep.NewCSRRequest(csr, &scep.PKIMessage{MessageType: kind, Recipients: []*x509.Certificate{decrypter}, SignerCert: signer, SignerKey: key})
}
