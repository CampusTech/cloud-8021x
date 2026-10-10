package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"
)

type pureECChain struct {
	root, intermediate, old, renewed            *x509.Certificate
	intermediateKey                             *ecdsa.PrivateKey
	rootPEM, intermediatePEM, clientPEM, keyPEM []byte
	now                                         time.Time
}

func pureECFixture(t *testing.T) pureECChain {
	t.Helper()
	now := time.Now().UTC()
	key := func() *ecdsa.PrivateKey {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		return k
	}
	rootKey, intermediateKey, clientKey := key(), key(), key()
	issue := func(template, parent *x509.Certificate, public *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
		der, e := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
		if e != nil {
			t.Fatal(e)
		}
		c, e := x509.ParseCertificate(der)
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	ca := func(serial int64, name string) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	}
	rootTemplate := ca(1, "task11 preserved EC root")
	root := issue(rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	intermediate := issue(ca(2, "task11 preserved EC intermediate"), root, &intermediateKey.PublicKey, rootKey)
	leaf := func(serial int64) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "11111111-2222-4333-8444-555555555555"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	}
	old := issue(leaf(3), intermediate, &clientKey.PublicKey, intermediateKey)
	renewed := issue(leaf(4), intermediate, &clientKey.PublicKey, intermediateKey)
	enc := func(c *x509.Certificate) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	private, e := x509.MarshalPKCS8PrivateKey(clientKey)
	if e != nil {
		t.Fatal(e)
	}
	return pureECChain{intermediateKey: intermediateKey, root: root, intermediate: intermediate, old: old, renewed: renewed, rootPEM: enc(root), intermediatePEM: enc(intermediate), clientPEM: append(enc(old), enc(intermediate)...), keyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), now: now}
}
func (f pureECChain) plan() ecClientPlan {
	return ecClientPlan{Phase: "original", Peer: "10.203.11.31", DNS: "ec.task11.test", RootSHA256: digestBytes(f.rootPEM), IntermediateSHA256: digestBytes(f.intermediatePEM), ClientCertificateSHA256: digestBytes(f.clientPEM), ClientKeySHA256: digestBytes(f.keyPEM)}
}
func TestECClientUsesExactOriginalMTLSAndFixed8443(t *testing.T) {
	f := pureECFixture(t)
	p := f.plan()
	client, e := pinnedECClient(p, f.rootPEM, f.intermediatePEM, f.clientPEM, f.keyPEM)
	if e != nil {
		t.Fatal(e)
	}
	if client == nil {
		t.Fatal("actual EC transport unavailable")
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil {
		t.Fatal("actual TLS transport missing")
	}
	cfg := tr.TLSClientConfig
	roots := x509.NewCertPool()
	roots.AddCert(f.root)
	if cfg.InsecureSkipVerify || cfg.ServerName != p.DNS || cfg.MinVersion < tls.VersionTLS12 || !cfg.RootCAs.Equal(roots) || tr.Proxy != nil || client.CheckRedirect == nil || client.Timeout > 5*time.Second || len(cfg.Certificates) != 1 || len(cfg.Certificates[0].Certificate) != 2 || !bytes.Equal(cfg.Certificates[0].Certificate[0], f.old.Raw) || !bytes.Equal(cfg.Certificates[0].Certificate[1], f.intermediate.Raw) {
		t.Fatal("EC mTLS identity/trust/bounds changed")
	}
	// Wrong port/name refuses synchronously, before any actual socket can be opened.
	if tr.DialContext == nil {
		t.Fatal("fixed private dial missing")
	}
	if _, e := tr.DialContext(context.Background(), "tcp4", "ec.task11.test:8444"); e == nil {
		t.Fatal("RSA port accepted for EC renewal")
	}
	request, e := makeECRenewRequest(p)
	if e != nil {
		t.Fatal(e)
	}
	if request.Method != "POST" || request.URL.String() != "https://ec.task11.test:8443/renew" || request.Body != nil && request.Body != http.NoBody || len(request.Header) != 0 {
		t.Fatal("renewal replaced with CSR/token/alternate endpoint")
	}
}
func TestECClientRefusesChangedProtectedInputs(t *testing.T) {
	f := pureECFixture(t)
	for _, change := range []string{"root", "intermediate", "client", "key", "peer", "phase"} {
		t.Run(change, func(t *testing.T) {
			p := f.plan()
			root, intermediate, client, key := f.rootPEM, f.intermediatePEM, f.clientPEM, f.keyPEM
			switch change {
			case "root":
				root = append(bytes.Clone(root), 'x')
			case "intermediate":
				intermediate = append(bytes.Clone(intermediate), 'x')
			case "client":
				client = append(bytes.Clone(client), 'x')
			case "key":
				key = append(bytes.Clone(key), 'x')
			case "peer":
				p.Peer = "10.203.11.40"
			case "phase":
				p.Phase = "unknown"
			}
			if _, e := pinnedECClient(p, root, intermediate, client, key); e == nil {
				t.Fatal("changed protected input accepted")
			}
		})
	}
}
func pureRenewJSON(t *testing.T, leaf, intermediate *x509.Certificate) []byte {
	t.Helper()
	enc := func(c *x509.Certificate) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	raw, e := json.Marshal(map[string]any{"crt": enc(leaf), "ca": enc(intermediate), "certChain": []string{enc(leaf), enc(intermediate)}, "tlsOptions": map[string]any{"cipherSuites": []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"}, "minVersion": 1.2, "maxVersion": 1.3, "renegotiation": false}})
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func TestECReplyVerifiesGenuineNewLeafAndPreservedIdentity(t *testing.T) {
	f := pureECFixture(t)
	body := pureRenewJSON(t, f.renewed, f.intermediate)
	leaf, e := verifyECRenewResponse(http.StatusCreated, body, f.old, f.root, f.intermediate, f.now)
	if e != nil {
		t.Fatal(e)
	}
	if leaf == nil || !bytes.Equal(leaf.Raw, f.renewed.Raw) || leaf.SerialNumber.String() != "4" {
		t.Fatal("genuine returned DER/serial not preserved")
	}
	for _, bad := range []string{"old-leaf", "untrusted-intermediate", "wrong-key", "wrong-subject", "server-auth", "expired", "unknown-field", "duplicate-crt", "trailing-json", "tls-version", "status"} {
		t.Run(bad, func(t *testing.T) {
			status := http.StatusCreated
			b := bytes.Clone(body)
			root, intermediate := f.root, f.intermediate
			switch bad {
			case "old-leaf":
				b = pureRenewJSON(t, f.old, f.intermediate)
			case "untrusted-intermediate":
				other := pureECFixture(t)
				intermediate = other.intermediate
				root = other.root
			case "wrong-key", "wrong-subject", "server-auth", "expired":
				template := *f.renewed
				public := f.old.PublicKey
				switch bad {
				case "wrong-key":
					other := pureECFixture(t)
					public = other.old.PublicKey
				case "wrong-subject":
					template.Subject = pkix.Name{CommonName: "foreign-client"}
					template.RawSubject = nil
				case "server-auth":
					template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
					template.ExtraExtensions = nil
				case "expired":
					template.NotAfter = f.now.Add(-time.Second)
				}
				der, err := x509.CreateCertificate(rand.Reader, &template, f.intermediate, public, f.intermediateKey)
				if err != nil {
					t.Fatal(err)
				}
				candidate, err := x509.ParseCertificate(der)
				if err != nil {
					t.Fatal(err)
				}
				b = pureRenewJSON(t, candidate, f.intermediate)
			case "unknown-field":
				b = append([]byte(`{"unknown":true,`), b[1:]...)
			case "duplicate-crt":
				oldPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.old.Raw}))
				value, err := json.Marshal(oldPEM)
				if err != nil {
					t.Fatal(err)
				}
				b = append(append([]byte(`{"crt":`), value...), append([]byte(","), b[1:]...)...)
			case "trailing-json":
				b = append(b, []byte(` {}`)...)
			case "tls-version":
				b = bytes.Replace(b, []byte(`"minVersion":1.2`), []byte(`"minVersion":1.25`), 1)
			case "status":
				status = http.StatusOK
			}
			if _, e := verifyECRenewResponse(status, b, f.old, root, intermediate, f.now); e == nil {
				t.Fatal("unverified/old/foreign renewal accepted")
			}
		})
	}
}
