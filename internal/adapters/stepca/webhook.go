package stepca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"time"
)

// LoopbackTLS preserves the existing distinct webhook identity: a non-CA,
// serverAuth-only P-256 leaf for localhost/127.0.0.1, trusted by Smallstep via the
// installed public certificate. It cannot issue RADIUS or device certificates.
func LoopbackTLS(existing ServerCertificate, now time.Time) (ServerCertificate, error) {
	if len(existing.Certificate) > 0 || len(existing.Key) > 0 {
		c, e := parseCert(existing.Certificate)
		if e != nil {
			return ServerCertificate{}, errors.New("existing webhook certificate invalid")
		}
		key, e := parseKey(existing.Key)
		if e != nil {
			return ServerCertificate{}, errors.New("existing webhook private key invalid")
		}
		ec, ok := key.(*ecdsa.PrivateKey)
		if !ok || ec.Curve != elliptic.P256() || !sameKey(c.PublicKey, key.Public()) || c.IsCA || !c.BasicConstraintsValid || c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) != nil || len(c.DNSNames) != 1 || c.DNSNames[0] != "localhost" || len(c.IPAddresses) != 1 || !c.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) || len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || now.Before(c.NotBefore) {
			return ServerCertificate{}, errors.New("existing webhook identity rejected")
		}
		if c.NotAfter.After(now.Add(30 * 24 * time.Hour)) {
			return existing, nil
		}
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return ServerCertificate{}, errors.New("webhook key generation failed")
	}
	n, e := serial()
	if e != nil {
		return ServerCertificate{}, e
	}
	leaf := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(365 * 24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, leaf, leaf, key.Public(), key)
	if e != nil {
		return ServerCertificate{}, errors.New("webhook certificate generation failed")
	}
	kb, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return ServerCertificate{}, e
	}
	return ServerCertificate{Certificate: certPEM(der), Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})}, nil
}
