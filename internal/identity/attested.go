package identity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"time"
)

var provisionerOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 1}
var permanentIdentifierOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 3}

func shortDER(tag byte, value []byte) []byte {
	if len(value) >= 128 {
		return nil
	}
	return append([]byte{tag, byte(len(value))}, value...)
}
func certificatePEM(data []byte) *x509.Certificate {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytesTrimSpace(rest)) != 0 {
		return nil
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return c
}

// RecognizeAttested is deliberately conservative. Failure falls back to fingerprint
// authorization; a matching CN, issuer label or caller assertion grants nothing.
func RecognizeAttested(leafPEM, issuerPEM []byte, provisioner string, now time.Time) string {
	leaf, issuer := certificatePEM(leafPEM), certificatePEM(issuerPEM)
	if leaf == nil || issuer == nil {
		return ""
	}
	if _, ok := issuer.PublicKey.(*ecdsa.PublicKey); !ok {
		return ""
	}
	if !bytes.Equal(leaf.RawIssuer, issuer.RawSubject) || issuer.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) != nil || !issuer.BasicConstraintsValid || !issuer.IsCA || leaf.IsCA {
		return ""
	}
	for _, c := range []*x509.Certificate{leaf, issuer} {
		if now.Before(c.NotBefore) || !now.Before(c.NotAfter) {
			return ""
		}
	}
	clientAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			clientAuth = true
		}
	}
	if !clientAuth {
		return ""
	}
	cn := ""
	count := 0
	for _, attr := range leaf.Subject.Names {
		if attr.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 3}) {
			count++
			value, ok := attr.Value.(string)
			if !ok {
				return ""
			}
			cn = value
		}
	}
	if count != 1 || !serialPattern.MatchString(cn) {
		return ""
	}
	for _, c := range []byte(provisioner) {
		if c > 127 {
			return ""
		}
	}
	name := shortDER(4, []byte(provisioner))
	if name == nil {
		return ""
	}
	marker := shortDER(48, append(append([]byte{2, 1, 6}, name...), 4, 0))
	if marker == nil {
		return ""
	}
	markerFound := false
	var san []byte
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(provisionerOID) {
			if markerFound || !bytes.Equal(ext.Value, marker) {
				return ""
			}
			markerFound = true
		}
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			if san != nil {
				return ""
			}
			san = ext.Value
		}
	}
	if !markerFound || san == nil {
		return ""
	}
	var sequence asn1.RawValue
	rest, err := asn1.Unmarshal(san, &sequence)
	if err != nil || len(rest) != 0 || sequence.Class != 0 || sequence.Tag != 16 || !sequence.IsCompound {
		return ""
	}
	remaining := sequence.Bytes
	ids := [][]byte{}
	for len(remaining) > 0 {
		var gn asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &gn)
		if err != nil {
			return ""
		}
		if gn.Class != 2 || gn.Tag != 0 {
			continue
		}
		var oid asn1.ObjectIdentifier
		value, err := asn1.Unmarshal(gn.Bytes, &oid)
		if err != nil {
			return ""
		}
		var explicit asn1.RawValue
		rest, err := asn1.Unmarshal(value, &explicit)
		if err != nil || len(rest) != 0 || explicit.Class != 2 || explicit.Tag != 0 || !explicit.IsCompound {
			return ""
		}
		if oid.Equal(permanentIdentifierOID) {
			ids = append(ids, explicit.Bytes)
		}
	}
	expected := shortDER(48, shortDER(12, []byte(cn)))
	if len(ids) != 1 || !bytes.Equal(ids[0], expected) {
		return ""
	}
	return cn
}
