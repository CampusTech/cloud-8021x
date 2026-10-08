package stepca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"regexp"
	"time"
)

type ServerCertificate struct{ Certificate, Key, Chain []byte }

// Certificates is the privileged server-leaf boundary; client ACME/SCEP issuance
// remains in step-ca. No caller CSR, arbitrary SAN, profile or signing operation
// is exposed through the application command.
type Certificates interface {
	Renew(context.Context) (ServerCertificate, error)
	Ready(context.Context) error
}
type ServerBackend struct {
	LocalCache                            ServerCertificate
	Store                                 Secrets
	Gate                                  Gate
	Signer                                crypto.Signer
	CA                                    Material
	DNSName, CertificateSecret, KeySecret string
	Now                                   func() time.Time
}

func (b *ServerBackend) Ready(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if b.Signer == nil {
		return errors.New("server issuer unavailable")
	}
	return Validate(b.CA, EC, b.Signer.Public(), b.now())
}
func (b *ServerBackend) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}
func (b *ServerBackend) Renew(ctx context.Context) (ServerCertificate, error) {
	var result ServerCertificate
	if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$`).MatchString(b.DNSName) || b.Store == nil || b.Gate == nil || b.CertificateSecret == "" || b.KeySecret == "" || b.CertificateSecret == b.KeySecret {
		return result, errors.New("invalid protected server certificate configuration")
	}
	if e := b.Ready(ctx); e != nil {
		return result, e
	}
	local, e := normalizeLocalServerCache(b.LocalCache, b.CA)
	if e != nil {
		return result, e
	}
	if len(local.Certificate) > 0 {
		if e = ValidateServerCache(local, b.CA, b.DNSName, b.now()); e != nil {
			return result, errors.New("installed server identity rejected; explicit recovery required")
		}
	}
	e = b.Gate.With(ctx, "server-certificate", func(ctx context.Context) error {
		v, e := b.Store.Enabled(ctx, b.CertificateSecret)
		if e != nil {
			return errors.New("server cache version lookup failed")
		}
		k, e := b.Store.Enabled(ctx, b.KeySecret)
		if e != nil {
			return errors.New("server key cache version lookup failed")
		}
		if len(v) > 0 && len(k) > 0 {
			cert, e := b.Store.Access(ctx, v[0])
			if e != nil {
				return errors.New("existing server certificate unreadable")
			}
			key, e := b.Store.Access(ctx, k[0])
			if e != nil {
				return errors.New("existing server key unreadable")
			}
			candidate := ServerCertificate{Certificate: cert, Key: key}
			if e := ValidateServerCache(candidate, b.CA, b.DNSName, b.now()); e != nil {
				return errors.New("existing server cache identity rejected; explicit recovery required")
			}
			if ValidateServer(candidate, b.CA, b.DNSName, b.now(), 30*24*time.Hour) == nil {
				candidate.Chain = append(append([]byte(nil), cert...), b.CA.Intermediate...)
				result = candidate
				return nil
			}
		}
		if (len(v) == 0) != (len(k) == 0) {
			return errors.New("server cache partially published; explicit recovery required")
		}
		candidate := local
		if len(v) > 0 || len(candidate.Certificate) == 0 || ValidateServer(candidate, b.CA, b.DNSName, b.now(), 30*24*time.Hour) != nil {
			candidate, e = b.issue(ctx)
			if e != nil {
				return e
			}
		}
		// Key first, certificate last. A crash can leave a mismatched pair, which
		// fails validation on recovery; neither half is treated as an issuance proof.
		for _, item := range []struct {
			name string
			data []byte
		}{{b.KeySecret, candidate.Key}, {b.CertificateSecret, candidate.Certificate}} {
			version, e := b.Store.Add(ctx, item.name, item.data)
			if e != nil {
				return errors.New("server certificate cache publication uncertain")
			}
			stored, e := b.Store.Access(ctx, version)
			if e != nil || string(stored) != string(item.data) {
				return errors.New("server certificate cache readback failed")
			}
		}
		result = candidate
		return nil
	})
	return result, e
}
func ValidateServer(s ServerCertificate, ca Material, dns string, now time.Time, minRemaining time.Duration) error {
	leaf, e := parseCert(s.Certificate)
	if e != nil {
		return e
	}
	root, e := parseCert(ca.Root)
	if e != nil {
		return e
	}
	intermediate, e := parseCert(ca.Intermediate)
	if e != nil {
		return e
	}
	key, e := parseKey(s.Key)
	if e != nil {
		return e
	}
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	inters.AddCert(intermediate)
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, CurrentTime: now, DNSName: dns, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); e != nil {
		return errors.New("server certificate chain, identity or validity rejected")
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != dns || len(leaf.IPAddresses) != 0 || len(leaf.URIs) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.UnknownExtKeyUsage) != 0 {
		return errors.New("server certificate SAN or usage rejected")
	}
	if leaf.IsCA || !sameKey(leaf.PublicKey, key.Public()) || leaf.CheckSignatureFrom(intermediate) != nil || !leaf.NotAfter.After(now.Add(minRemaining)) {
		return errors.New("server certificate key, issuer or renewal interval rejected")
	}
	// Compatible legacy Smallstep leaves may include clientAuth too. New leaves
	// deliberately grant only serverAuth. Never accept a CA or unconstrained EKU.
	hasServer := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage != x509.ExtKeyUsageServerAuth && usage != x509.ExtKeyUsageClientAuth {
			return errors.New("unconstrained server certificate usage")
		}
		hasServer = hasServer || usage == x509.ExtKeyUsageServerAuth
	}
	if !hasServer {
		return errors.New("serverAuth usage required")
	}
	return nil
}
func (b *ServerBackend) issue(ctx context.Context) (ServerCertificate, error) {
	if e := ctx.Err(); e != nil {
		return ServerCertificate{}, e
	}
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		return ServerCertificate{}, errors.New("server key creation failed")
	}
	intermediate, e := parseCert(b.CA.Intermediate)
	if e != nil {
		return ServerCertificate{}, e
	}
	serial, e := serial()
	if e != nil {
		return ServerCertificate{}, e
	}
	now := b.now()
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: b.DNSName}, DNSNames: []string{b.DNSName}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2160 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	signer := b.Signer
	if contextual, ok := signer.(interface {
		WithContext(context.Context) crypto.Signer
	}); ok {
		signer = contextual.WithContext(ctx)
	}
	der, e := x509.CreateCertificate(rand.Reader, leaf, intermediate, key.Public(), signer)
	if e != nil {
		return ServerCertificate{}, errors.New("server certificate signing failed")
	}
	keyDER, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return ServerCertificate{}, errors.New("server key encoding failed")
	}
	result := ServerCertificate{Certificate: certPEM(der), Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})}
	result.Chain = append(append([]byte(nil), result.Certificate...), b.CA.Intermediate...)
	if e = ValidateServer(result, b.CA, b.DNSName, now, 30*24*time.Hour); e != nil {
		return ServerCertificate{}, e
	}
	return result, nil
}

// ValidateServerCache distinguishes a legitimate expired/due leaf from malformed
// or foreign material. Expiry alone may renew; identity/key/trust failures may not.
func ValidateServerCache(s ServerCertificate, ca Material, dns string, now time.Time) error {
	leaf, err := parseCert(s.Certificate)
	if err != nil || leaf.NotBefore.After(now) {
		return errors.New("server cache certificate rejected")
	}
	at := now
	if !leaf.NotAfter.After(at) {
		at = leaf.NotAfter.Add(-time.Second)
	}
	return ValidateServer(s, ca, dns, at, 0)
}

func normalizeLocalServerCache(s ServerCertificate, ca Material) (ServerCertificate, error) {
	if len(s.Certificate) == 0 && len(s.Key) == 0 {
		return s, nil
	}
	block, rest := pem.Decode(s.Certificate)
	if block == nil || block.Type != "CERTIFICATE" || len(s.Key) == 0 {
		return s, errors.New("partial or malformed installed server cache")
	}
	leaf := pem.EncodeToMemory(block)
	if len(bytes.TrimSpace(rest)) > 0 {
		cert, e := parseCert(rest)
		issuer, ie := parseCert(ca.Intermediate)
		if e != nil || ie != nil || !bytes.Equal(cert.Raw, issuer.Raw) {
			return s, errors.New("installed server chain differs from preserved issuer")
		}
	}
	s.Certificate = leaf
	s.Chain = append(append([]byte(nil), leaf...), ca.Intermediate...)
	return s, nil
}
