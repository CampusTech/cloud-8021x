package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"
)

// EC renewal is the installed original legacy client's genuine mTLS route.
// This independent client does not add an ACME provisioner or change CA policy.
type ecClientPlan struct {
	Phase                   string `json:"phase"`
	Peer                    string `json:"peer"`
	DNS                     string `json:"dns"`
	RootSHA256              string `json:"root_sha256"`
	IntermediateSHA256      string `json:"intermediate_sha256"`
	ClientCertificateSHA256 string `json:"client_certificate_sha256"`
	ClientKeySHA256         string `json:"client_key_sha256"`
}

func validateECPlan(p ecClientPlan) error {
	allowed := false
	switch p.Phase {
	case "original":
		allowed = p.Peer == "10.203.11.31" || p.Peer == "10.203.11.32"
	case "adopted", "passive":
		allowed = p.Peer == "10.203.11.21" || p.Peer == "10.203.11.22"
	}
	if !allowed || !fixtureDNSPattern.MatchString(p.DNS) || strings.Contains(p.DNS, "..") {
		return errors.New("closed EC phase/authority required")
	}
	for _, pin := range []string{p.RootSHA256, p.IntermediateSHA256, p.ClientCertificateSHA256, p.ClientKeySHA256} {
		if !shaPattern.MatchString(pin) {
			return errors.New("original EC material pins required")
		}
	}
	return nil
}
func pinnedECClient(p ecClientPlan, rootPEM, intermediatePEM, clientPEM, keyPEM []byte) (*http.Client, error) {
	if e := validateECPlan(p); e != nil {
		return nil, e
	}
	root, e := singlePinnedCertificate(rootPEM, p.RootSHA256)
	if e != nil || !root.IsCA {
		return nil, errors.New("preserved EC root required")
	}
	intermediate, e := singlePinnedCertificate(intermediatePEM, p.IntermediateSHA256)
	if e != nil || !intermediate.IsCA || intermediate.CheckSignatureFrom(root) != nil {
		return nil, errors.New("preserved EC intermediate required")
	}
	if len(clientPEM) > 64<<10 || len(keyPEM) > 16<<10 || digestBytes(clientPEM) != p.ClientCertificateSHA256 || digestBytes(keyPEM) != p.ClientKeySHA256 {
		return nil, errors.New("original EC client pins differ")
	}
	block, rest := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("single original PKCS8 client key required")
	}
	parsed, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	clear(block.Bytes)
	private, ok := parsed.(*ecdsa.PrivateKey)
	if e != nil || !ok || private.Curve != elliptic.P256() {
		return nil, errors.New("original EC P256 client key required")
	}
	pair, e := tls.X509KeyPair(clientPEM, keyPEM)
	if e != nil || len(pair.Certificate) != 2 || !bytes.Equal(pair.Certificate[1], intermediate.Raw) {
		return nil, errors.New("exact original client chain required")
	}
	old, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil || old.IsCA || len(old.ExtKeyUsage) != 1 || old.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || !bytes.Equal(old.RawIssuer, intermediate.RawSubject) {
		return nil, errors.New("original client-only leaf required")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)
	if _, e := old.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: time.Now().UTC()}); e != nil {
		return nil, errors.New("original EC client chain invalid")
	}
	expected := net.JoinHostPort(p.DNS, "8443")
	target := net.JoinHostPort(p.Peer, "8443")
	dialer := &net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("10.203.11.40")}}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: p.DNS, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}, DisableKeepAlives: true, MaxConnsPerHost: 1, ResponseHeaderTimeout: 4 * time.Second, MaxResponseHeaderBytes: 32 << 10, ForceAttemptHTTP2: false, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if (network != "tcp" && network != "tcp4") || address != expected {
			return nil, errors.New("EC destination outside fixed private authority")
		}
		return dialer.DialContext(ctx, "tcp4", target)
	}}
	return &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
func makeECRenewRequest(p ecClientPlan) (*http.Request, error) {
	if e := validateECPlan(p); e != nil {
		return nil, e
	}
	return http.NewRequest(http.MethodPost, "https://"+net.JoinHostPort(p.DNS, "8443")+"/renew", http.NoBody)
}

type ecTLSOptions struct {
	CipherSuites  []string `json:"cipherSuites"`
	MinVersion    float64  `json:"minVersion"`
	MaxVersion    float64  `json:"maxVersion"`
	Renegotiation bool     `json:"renegotiation"`
}
type ecRenewReply struct {
	Certificate string        `json:"crt"`
	CA          string        `json:"ca"`
	Chain       []string      `json:"certChain"`
	TLSOptions  *ecTLSOptions `json:"tlsOptions,omitempty"`
}

func verifyECRenewResponse(status int, body []byte, old, root, intermediate *x509.Certificate, now time.Time) (*x509.Certificate, error) {
	if status != http.StatusCreated || old == nil || root == nil || intermediate == nil || now.IsZero() || !root.IsCA || !intermediate.IsCA || intermediate.CheckSignatureFrom(root) != nil {
		return nil, errors.New("actual201/preserved EC chain required")
	}
	var reply ecRenewReply
	if e := strictJSON(body, 32<<10, &reply); e != nil {
		return nil, e
	}
	if len(reply.Chain) != 2 || reply.Certificate != reply.Chain[0] || reply.CA != reply.Chain[1] {
		return nil, errors.New("exact returned EC chain required")
	}
	if o := reply.TLSOptions; o != nil {
		if (o.MinVersion != 1.2 && o.MinVersion != 1.3) || (o.MaxVersion != 1.2 && o.MaxVersion != 1.3) || o.MaxVersion < o.MinVersion || o.Renegotiation || len(o.CipherSuites) > 16 {
			return nil, errors.New("unsupported returned TLS policy")
		}
		for _, name := range o.CipherSuites {
			if len(name) > 128 || !strings.HasPrefix(name, "TLS_") {
				return nil, errors.New("invalid returned cipher metadata")
			}
		}
	}
	leaf, e := singlePinnedCertificate([]byte(reply.Certificate), digestBytes([]byte(reply.Certificate)))
	if e != nil {
		return nil, e
	}
	returnedCA, e := singlePinnedCertificate([]byte(reply.CA), digestBytes([]byte(reply.CA)))
	if e != nil || !bytes.Equal(returnedCA.Raw, intermediate.Raw) {
		return nil, errors.New("returned intermediate differs")
	}
	if leaf.IsCA || leaf.SerialNumber.Sign() <= 0 || bytes.Equal(leaf.Raw, old.Raw) || leaf.SerialNumber.Cmp(old.SerialNumber) == 0 || !bytes.Equal(leaf.RawSubjectPublicKeyInfo, old.RawSubjectPublicKeyInfo) || !bytes.Equal(leaf.RawSubject, old.RawSubject) || !bytes.Equal(leaf.RawIssuer, intermediate.RawSubject) || leaf.KeyUsage != old.KeyUsage || !reflect.DeepEqual(leaf.ExtKeyUsage, old.ExtKeyUsage) || !reflect.DeepEqual(leaf.UnknownExtKeyUsage, old.UnknownExtKeyUsage) || !reflect.DeepEqual(leaf.DNSNames, old.DNSNames) || !reflect.DeepEqual(leaf.IPAddresses, old.IPAddresses) || !reflect.DeepEqual(leaf.EmailAddresses, old.EmailAddresses) || !reflect.DeepEqual(leaf.URIs, old.URIs) || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		return nil, errors.New("renewed legacy client identity changed")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)
	if _, e := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
		return nil, errors.New("renewed EC chain invalid")
	}
	return leaf, nil
}
