package stepca

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"time"
)

// ValidateAdoptedLoopback validates the original identity without renewal.
func ValidateAdoptedLoopback(cert, key []byte, now time.Time) error {
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil || len(pair.Certificate) != 1 {
		return errors.New("original webhook key pair rejected")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	if leaf.IsCA || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) != nil || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "localhost" || len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "127.0.0.1" || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		return errors.New("original webhook identity rejected")
	}
	return nil
}

// ValidateAdoptedConfig compares parsed values against the fixed supported
// configuration and retains the original byte representation. This refuses a
// changed DB/KMS/provisioner/template/webhook identity instead of rewriting it.
func ValidateAdoptedConfig(original, expected []byte) error {
	var a, b any
	dec := json.NewDecoder(bytes.NewReader(original))
	dec.UseNumber()
	if dec.Decode(&a) != nil || dec.Decode(new(any)) != io.EOF {
		return errors.New("invalid original CA configuration")
	}
	dec = json.NewDecoder(bytes.NewReader(expected))
	dec.UseNumber()
	if dec.Decode(&b) != nil || dec.Decode(new(any)) != io.EOF || !reflect.DeepEqual(a, b) {
		return errors.New("original CA configuration differs from pinned preserved configuration")
	}
	return nil
}
