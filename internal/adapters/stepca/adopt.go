package stepca

import (
	"context"
	"crypto"
	"errors"
	"time"
)

// ReadOnlySecrets deliberately excludes publication. Passive green preparation
// cannot initialize, recover or renew shared CA state even when all reads say
// absent. A source deployment must resolve partial publication first.
type ReadOnlySecrets interface {
	Enabled(context.Context, string) ([]string, error)
	Access(context.Context, string) ([]byte, error)
}

func existingSecret(ctx context.Context, store ReadOnlySecrets, name string) ([]byte, error) {
	versions, err := store.Enabled(ctx, name)
	if err != nil || len(versions) == 0 {
		return nil, errors.New("adoption requires an existing enabled secret version")
	}
	value, err := store.Access(ctx, versions[0])
	if err != nil || len(value) == 0 {
		return nil, errors.New("adoption secret version unavailable")
	}
	return value, nil
}

// Adopt verifies the full certificate chain and actual pinned KMS public key,
// including the SCEP decrypter certificate/private key relationship. Names alone
// never establish CA identity; no signing operation is required or available.
func Adopt(ctx context.Context, store ReadOnlySecrets, d Definition, key crypto.PublicKey, now time.Time) (Material, error) {
	if store == nil || key == nil || d.Name == "" || (d.Kind != EC && d.Kind != RSA) {
		return Material{}, errors.New("invalid CA adoption dependencies")
	}
	names := []string{d.RootSecret, d.IntermediateSecret, d.DecrypterCertSecret, d.DecrypterKeySecret}
	seen := map[string]bool{}
	values := make([][]byte, 4)
	for i, name := range names {
		if name == "" || seen[name] {
			return Material{}, errors.New("CA adoption requires distinct fixed secrets")
		}
		seen[name] = true
		var err error
		values[i], err = existingSecret(ctx, store, name)
		if err != nil {
			return Material{}, err
		}
	}
	material := Material{Root: values[0], Intermediate: values[1], DecrypterCert: values[2], DecrypterKey: values[3]}
	if err := Validate(material, d.Kind, key, now); err != nil {
		return Material{}, err
	}
	return material, nil
}

// AdoptServer preserves the existing shared server leaf and key exactly. It
// refuses missing, partial, mismatched and expired state instead of renewing it.
func AdoptServer(ctx context.Context, store ReadOnlySecrets, ca Material, dns, certificateSecret, keySecret string, now time.Time) (ServerCertificate, error) {
	if store == nil || certificateSecret == "" || keySecret == "" || certificateSecret == keySecret {
		return ServerCertificate{}, errors.New("invalid server adoption references")
	}
	certificate, err := existingSecret(ctx, store, certificateSecret)
	if err != nil {
		return ServerCertificate{}, err
	}
	key, err := existingSecret(ctx, store, keySecret)
	if err != nil {
		return ServerCertificate{}, err
	}
	result := ServerCertificate{Certificate: certificate, Key: key}
	if err = ValidateServer(result, ca, dns, now, 0); err != nil {
		return ServerCertificate{}, err
	}
	result.Chain = append(append([]byte(nil), certificate...), ca.Intermediate...)
	return result, nil
}
