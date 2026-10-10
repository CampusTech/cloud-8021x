// Package stepca implements the existing independent EC and RSA Smallstep CAs.
package stepca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"time"
)

type Kind string

const (
	EC  Kind = "ec"
	RSA Kind = "rsa"
)

type Definition struct {
	Kind                                                                          Kind
	Name, RootSecret, IntermediateSecret, DecrypterCertSecret, DecrypterKeySecret string
	StagingSecret                                                                 string
}
type Material struct{ Root, Intermediate, DecrypterCert, DecrypterKey []byte }

// Secrets distinguishes a successful empty enabled-version list from every API
// failure. Access always names the exact enabled version returned by the list.
type Secrets interface {
	Enabled(context.Context, string) ([]string, error)
	Access(context.Context, string) ([]byte, error)
	Add(context.Context, string, []byte) (string, error)
}

// Gate must serialize all nodes, including publication and readback, without a
// time-expiring lease that could permit another publisher while this one runs.
type Gate interface {
	With(context.Context, string, func(context.Context) error) error
}

// Publication stores public recovery metadata only. The complete private SCEP
// bundle lives in the fixed root-only Secret Manager staging secret.
type Publication struct {
	Secret, SHA256, Version string
	Published               bool
}
type Journal interface {
	Load(context.Context, string) (Publication, error)
	Begin(context.Context, string, Publication) error
	Bind(context.Context, string, string) error
	Published(context.Context, string) error
}
type Manager struct {
	Journal Journal
	Store   Secrets
	Gate    Gate
	Now     func() time.Time
}

func (m *Manager) Ensure(ctx context.Context, d Definition, signer crypto.Signer) (Material, error) {
	var result Material
	if m.Store == nil || m.Gate == nil || signer == nil || d.Name == "" || (d.Kind != EC && d.Kind != RSA) {
		return result, errors.New("CA dependencies unavailable")
	}
	names := []string{d.RootSecret, d.DecrypterCertSecret, d.DecrypterKeySecret, d.IntermediateSecret}
	seen := map[string]bool{}
	for _, n := range names {
		if n == "" || seen[n] {
			return result, errors.New("CA secret references must be distinct")
		}
		seen[n] = true
	}
	now := time.Now
	if m.Now != nil {
		now = m.Now
	}
	err := m.Gate.With(ctx, "ca-initialization", func(ctx context.Context) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		versions := make([]string, 4)
		present := 0
		for i, n := range names {
			v, e := m.Store.Enabled(ctx, n)
			if e != nil {
				return errors.New("CA enabled-version lookup failed; refusing initialization")
			}
			if len(v) > 0 {
				versions[i] = v[0]
				present++
			}
		}

		parts := make([][]byte, 4)
		for i, v := range versions {
			if v == "" {
				continue
			}
			b, e := m.Store.Access(ctx, v)
			if e != nil || len(b) == 0 {
				return errors.New("existing CA version unreadable; refusing initialization")
			}
			parts[i] = b
		}
		pub, e := x509.MarshalPKIXPublicKey(signer.Public())
		if e != nil {
			return errors.New("invalid KMS public key")
		}
		identity, _ := json.Marshal(struct {
			Definition Definition
			PublicKey  []byte
		}{d, pub})
		hash := sha256.Sum256(identity)
		reference := hex.EncodeToString(hash[:])
		if present == 4 {
			result = Material{Root: parts[0], DecrypterCert: parts[1], DecrypterKey: parts[2], Intermediate: parts[3]}
			if e = Validate(result, d.Kind, signer.Public(), now()); e != nil {
				return e
			}
			if m.Journal == nil {
				return nil
			}
			saved, e := m.Journal.Load(ctx, reference)
			if e != nil {
				return errors.New("CA publication journal unavailable")
			}
			if saved.Secret == "" {
				return nil
			} // Complete, independently verified legacy CA.
			if saved.Secret != d.StagingSecret || saved.Version == "" {
				return errors.New("CA staging publication unresolved")
			}
			encoded, e := m.Store.Access(ctx, saved.Version)
			sum := sha256.Sum256(encoded)
			var original Material
			if e != nil || hex.EncodeToString(sum[:]) != saved.SHA256 || json.Unmarshal(encoded, &original) != nil || !bytes.Equal(original.Root, result.Root) || !bytes.Equal(original.Intermediate, result.Intermediate) || !bytes.Equal(original.DecrypterCert, result.DecrypterCert) || !bytes.Equal(original.DecrypterKey, result.DecrypterKey) {
				return errors.New("complete CA differs from original publication bundle")
			}
			if !saved.Published {
				return m.Journal.Published(ctx, reference)
			}
			return nil
		}
		if m.Journal == nil {
			return errors.New("durable CA recovery journal required before initialization")
		}
		if d.StagingSecret == "" || seen[d.StagingSecret] {
			return errors.New("distinct fixed CA staging secret required")
		}
		saved, e := m.Journal.Load(ctx, reference)
		if e != nil {
			return errors.New("CA recovery journal unavailable")
		}
		if saved.Published {
			return errors.New("previously ready CA state incomplete; explicit recovery required")
		}
		var material Material
		if saved.Secret != "" {
			if saved.Secret != d.StagingSecret || saved.Version == "" {
				return errors.New("CA staging publication unresolved; explicit reconciliation required")
			}
			encoded, e := m.Store.Access(ctx, saved.Version)
			if e != nil {
				return errors.New("original CA recovery version unavailable")
			}
			sum := sha256.Sum256(encoded)
			if hex.EncodeToString(sum[:]) != saved.SHA256 || json.Unmarshal(encoded, &material) != nil {
				return errors.New("original CA recovery bundle integrity failed")
			}
		} else {
			if present != 0 {
				return errors.New("CA state partially published without recovery bundle; trust will not be replaced")
			}
			versions, e := m.Store.Enabled(ctx, d.StagingSecret)
			if e != nil || len(versions) != 0 {
				return errors.New("unjournaled CA staging version requires explicit reconciliation")
			}
			if contextual, ok := signer.(interface {
				WithContext(context.Context) crypto.Signer
			}); ok {
				signer = contextual.WithContext(ctx)
			}
			material, e = initialize(d, signer, now())
			if e != nil {
				return e
			}
			if e = Validate(material, d.Kind, signer.Public(), now()); e != nil {
				return e
			}
			encoded, e := json.Marshal(material)
			if e != nil {
				return errors.New("CA recovery encoding failed")
			}
			sum := sha256.Sum256(encoded)
			attempt := Publication{Secret: d.StagingSecret, SHA256: hex.EncodeToString(sum[:])}
			// Persist expected identity/hash BEFORE the first remote staging I/O.
			if e = m.Journal.Begin(ctx, reference, attempt); e != nil {
				return errors.New("CA staging attempt persistence failed")
			}
			version, e := m.Store.Add(ctx, d.StagingSecret, encoded)
			if e != nil {
				return errors.New("CA staging publication uncertain; explicit reconciliation required")
			}
			stored, e := m.Store.Access(ctx, version)
			if e != nil || !bytes.Equal(encoded, stored) {
				return errors.New("CA staging readback failed; component publication withheld")
			}
			if e = m.Journal.Bind(ctx, reference, version); e != nil {
				return errors.New("CA staging version binding uncertain")
			}
			saved, e = m.Journal.Load(ctx, reference)
			if e != nil || saved.Secret != attempt.Secret || saved.SHA256 != attempt.SHA256 || saved.Version != version || saved.Published {
				return errors.New("CA staging journal readback failed")
			}
		}
		if e = Validate(material, d.Kind, signer.Public(), now()); e != nil {
			return e
		}
		wanted := [][]byte{material.Root, material.DecrypterCert, material.DecrypterKey, material.Intermediate}
		for i, n := range names {
			if len(parts[i]) > 0 {
				if !bytes.Equal(parts[i], wanted[i]) {
					return errors.New("published CA differs from original recovery bundle")
				}
				continue
			}
			// Gate owns publication. Every component is rechecked; readiness is last.
			v, e := m.Store.Enabled(ctx, n)
			if e != nil || len(v) != 0 {
				return errors.New("CA state changed during initialization")
			}
			version, e := m.Store.Add(ctx, n, wanted[i])
			if e != nil {
				return errors.New("CA publication uncertain; explicit recovery required")
			}
			stored, e := m.Store.Access(ctx, version)
			if e != nil || !bytes.Equal(stored, wanted[i]) {
				return errors.New("CA publication readback failed; readiness withheld")
			}
		}
		if e = m.Journal.Published(ctx, reference); e != nil {
			return errors.New("CA readiness journal uncertain; explicit reconciliation required")
		}

		result = material
		return nil
	})
	return result, err
}
func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
func parseCert(b []byte) (*x509.Certificate, error) {
	p, rest := pem.Decode(b)
	if p == nil || p.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid single CA certificate")
	}
	c, e := x509.ParseCertificate(p.Bytes)
	if e != nil {
		return nil, errors.New("invalid CA certificate")
	}
	return c, nil
}
func parseKey(b []byte) (crypto.Signer, error) {
	p, rest := pem.Decode(b)
	if p == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid private key")
	}
	var key any
	var e error
	switch p.Type {
	case "PRIVATE KEY":
		key, e = x509.ParsePKCS8PrivateKey(p.Bytes)
	case "RSA PRIVATE KEY":
		key, e = x509.ParsePKCS1PrivateKey(p.Bytes)
	case "EC PRIVATE KEY":
		key, e = x509.ParseECPrivateKey(p.Bytes)
	default:
		return nil, errors.New("unsupported private key")
	}
	s, ok := key.(crypto.Signer)
	if e != nil || !ok {
		return nil, errors.New("invalid private key")
	}
	return s, nil
}
func sameKey(a, b crypto.PublicKey) bool {
	aa, e := x509.MarshalPKIXPublicKey(a)
	bb, f := x509.MarshalPKIXPublicKey(b)
	return e == nil && f == nil && bytes.Equal(aa, bb)
}
func Validate(m Material, kind Kind, kms crypto.PublicKey, now time.Time) error {
	root, e := parseCert(m.Root)
	if e != nil {
		return e
	}
	intermediate, e := parseCert(m.Intermediate)
	if e != nil {
		return e
	}
	dec, e := parseCert(m.DecrypterCert)
	if e != nil {
		return e
	}
	key, e := parseKey(m.DecrypterKey)
	if e != nil {
		return e
	}
	for _, c := range []*x509.Certificate{root, intermediate, dec} {
		if now.Before(c.NotBefore) || !now.Before(c.NotAfter) {
			return errors.New("CA certificate outside validity")
		}
	}
	if !root.IsCA || !root.BasicConstraintsValid || root.CheckSignatureFrom(root) != nil || !intermediate.IsCA || !intermediate.BasicConstraintsValid || !intermediate.MaxPathLenZero || intermediate.CheckSignatureFrom(root) != nil || !sameKey(intermediate.PublicKey, kms) {
		return errors.New("CA chain or KMS key mismatch")
	}
	switch kind {
	case EC:
		r, ok := root.PublicKey.(*ecdsa.PublicKey)
		i, ok2 := intermediate.PublicKey.(*ecdsa.PublicKey)
		if !ok || !ok2 || r.Curve != elliptic.P256() || i.Curve != elliptic.P256() {
			return errors.New("EC CA requires P-256 keys")
		}
		if dec.CheckSignatureFrom(root) != nil {
			return errors.New("EC decrypter must chain to preserved root")
		}
	case RSA:
		r, ok := root.PublicKey.(*rsa.PublicKey)
		i, ok2 := intermediate.PublicKey.(*rsa.PublicKey)
		if !ok || !ok2 || r.N.BitLen() < 4096 || i.N.BitLen() < 2048 || dec.CheckSignatureFrom(intermediate) != nil {
			return errors.New("RSA CA topology or key size mismatch")
		}
	default:
		return errors.New("unknown CA kind")
	}
	dk, ok := key.(*rsa.PrivateKey)
	if !ok || dk.N.BitLen() < 2048 || dk.Validate() != nil || !sameKey(dec.PublicKey, key.Public()) || dec.IsCA {
		return errors.New("SCEP software RSA cert/key mismatch")
	}
	return nil
}
func serial() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)) }
func initialize(d Definition, kms crypto.Signer, now time.Time) (Material, error) {
	var rootKey crypto.Signer
	var e error
	switch d.Kind {
	case EC:
		rootKey, e = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case RSA:
		rootKey, e = rsa.GenerateKey(rand.Reader, 4096)
	default:
		return Material{}, errors.New("unknown CA kind")
	}
	if e != nil {
		return Material{}, errors.New("CA key generation failed")
	}
	n, e := serial()
	if e != nil {
		return Material{}, e
	}
	root := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: d.Name + " Root CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(20 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 1}
	der, e := x509.CreateCertificate(rand.Reader, root, root, rootKey.Public(), rootKey)
	if e != nil {
		return Material{}, errors.New("root certificate creation failed")
	}
	root, _ = x509.ParseCertificate(der)
	m := Material{Root: certPEM(der)}
	n, e = serial()
	if e != nil {
		return Material{}, e
	}
	intermediate := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: d.Name + " Intermediate CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 0, MaxPathLenZero: true}
	der, e = x509.CreateCertificate(rand.Reader, intermediate, root, kms.Public(), rootKey)
	if e != nil {
		return Material{}, errors.New("intermediate certificate creation failed")
	}
	intermediate, _ = x509.ParseCertificate(der)
	m.Intermediate = certPEM(der)
	decKey, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		return Material{}, errors.New("decrypter generation failed")
	}
	n, e = serial()
	if e != nil {
		return Material{}, e
	}
	dec := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: d.Name + " SCEP Decrypter"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * 365 * 24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	parent, signer := root, rootKey
	if d.Kind == RSA {
		parent, signer = intermediate, kms
	}
	der, e = x509.CreateCertificate(rand.Reader, dec, parent, decKey.Public(), signer)
	if e != nil {
		return Material{}, errors.New("decrypter signing failed")
	}
	m.DecrypterCert = certPEM(der)
	kb, e := x509.MarshalPKCS8PrivateKey(decKey)
	if e != nil {
		return Material{}, errors.New("decrypter encoding failed")
	}
	m.DecrypterKey = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})
	// Root keys never leave this call and are never restored or persisted.
	return m, nil
}
