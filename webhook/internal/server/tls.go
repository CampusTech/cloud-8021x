package server

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"strings"
)

// NewMutualTLS authenticates webhook requests exclusively through verified
// client TLS chains. Serve it with ClientTLSConfig; HMACs and proxy headers
// cannot substitute for mutual TLS in this mode.
func NewMutualTLS(signingKey string, d Decider) http.Handler {
	return (&handler{scepSigningKey: []byte(signingKey), decider: d, mutualTLS: true}).routes()
}

// ClientTLSConfig limits callers to an explicit CA trust bundle and the named
// step-ca internal TLS certificates, which carry both clientAuth and serverAuth.
// Wi-Fi client certificates therefore cannot authenticate as the CA webhook caller.
func ClientTLSConfig(rootPEM []byte, allowedDNSNames []string) (*tls.Config, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return nil, errors.New("webhook client CA bundle contains no valid certificates")
	}
	if len(allowedDNSNames) == 0 {
		return nil, errors.New("webhook client DNS allowlist is empty")
	}
	names := append([]string(nil), allowedDNSNames...)
	for _, name := range names {
		if name == "" || strings.ContainsAny(name, " \t\r\n*/") {
			return nil, errors.New("webhook client DNS allowlist contains an invalid name")
		}
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  roots,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
				return errors.New("webhook client certificate is not verified")
			}
			leaf := state.PeerCertificates[0]
			clientAuth, serverAuth := false, false
			for _, usage := range leaf.ExtKeyUsage {
				clientAuth = clientAuth || usage == x509.ExtKeyUsageClientAuth
				serverAuth = serverAuth || usage == x509.ExtKeyUsageServerAuth
			}
			if !clientAuth || !serverAuth {
				return errors.New("webhook client certificate must be a CA service TLS certificate")
			}
			for _, name := range names {
				if leaf.VerifyHostname(name) == nil {
					return nil
				}
			}
			return errors.New("webhook client certificate does not match an allowed CA service name")
		},
	}, nil
}
