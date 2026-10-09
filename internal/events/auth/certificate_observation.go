package auth

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"strings"
	"time"
)

// CertificateObservation is monitoring metadata, never policy input or identity.
// Device/fingerprint remain the existing independently verified Class attribution.
type CertificateObservation struct {
	ExpiresAt  int64  `json:"expires_at"`
	CAInstance string `json:"ca_instance"`
}

// WithCertificateExpiry runs after the existing Class-based enrichment. Raw
// native issuer/expiration values never become event identity or exported labels.
func WithCertificateExpiry(base func(*Event, Record), issuers map[string]string) func(*Event, Record) {
	names := make(map[string]string, len(issuers))
	for name, ca := range issuers {
		if ca == "ec" || ca == "rsa" || ca == "wifi" {
			names[name] = ca
		}
	}
	return func(e *Event, r Record) {
		base(e, r)
		if e.Event != "Access-Accept" || e.DeviceID == "" || e.Fingerprint == "" || len(names) == 0 {
			return
		}
		expiry, issuer := r.Values["C8021X-Cert-Expiration"], r.Values["C8021X-Cert-Issuer"]
		if len(expiry) != 1 || len(issuer) != 1 || len(issuer[0]) < 1 || len(issuer[0]) > 1023 || strings.ContainsAny(issuer[0], "\r\n\x00") {
			return
		}
		layout, tag := "060102150405Z", byte(asn1.TagUTCTime)
		if len(expiry[0]) == 15 {
			layout, tag = "20060102150405Z", byte(asn1.TagGeneralizedTime)
		} else if len(expiry[0]) != 13 {
			return
		}
		var expires time.Time
		rest, err := asn1.Unmarshal(append([]byte{tag, byte(len(expiry[0]))}, []byte(expiry[0])...), &expires)
		if err != nil || len(rest) != 0 || expires.Format(layout) != expiry[0] || !expires.After(e.Received) {
			return
		}
		ca := names[issuer[0]]
		if ca == "" {
			ca = "other"
		}
		e.CertificateObservation = &CertificateObservation{ExpiresAt: expires.Unix(), CAInstance: ca}
	}
}

// NativeIssuerName reproduces the pinned native OpenSSL oneline format for
// ordinary ASCII CA subjects. Unsupported/ambiguous encodings are unavailable,
// never a guessed CA classification. The adopted installation uses plain CNs.
func NativeIssuerName(raw []byte) (string, error) {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("issuer certificate unavailable")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA {
		return "", errors.New("issuer certificate invalid")
	}
	var sequence pkix.RDNSequence
	rest, err := asn1.Unmarshal(cert.RawSubject, &sequence)
	if err != nil || len(rest) != 0 {
		return "", errors.New("issuer name unavailable")
	}
	names := map[string]string{"2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.5": "serialNumber", "1.2.840.113549.1.9.1": "emailAddress", "0.9.2342.19200300.100.1.25": "DC"}
	var out strings.Builder
	for _, rdn := range sequence {
		if len(rdn) != 1 {
			return "", errors.New("issuer name unsupported")
		}
		short := names[rdn[0].Type.String()]
		value, ok := rdn[0].Value.(string)
		if !ok || short == "" || value == "" {
			return "", errors.New("issuer name unsupported")
		}
		for _, b := range []byte(value) {
			if b < 32 || b > 126 || b == '/' || b == '\\' || b == '+' {
				return "", errors.New("issuer name escaping unsupported")
			}
		}
		out.WriteString("/" + short + "=" + value)
	}
	if out.Len() == 0 || out.Len() > 1023 {
		return "", errors.New("issuer name exceeds native bound")
	}
	return out.String(), nil
}
