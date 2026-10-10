package stepca

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// ProbeSCEPDecrypter performs only GetCACert against the literal local RSA CA.
// Ready means the live, TLS-authenticated SCEP handler advertises the exact
// adopted, currently valid encryption certificate; it does not claim issuance.
func ProbeSCEPDecrypter(ctx context.Context, address, dns, provisioner string, trust, expected []byte) error {
	host, _, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !ip.IsLoopback() || dns == "" || provisioner == "" {
		return errors.New("local SCEP identity required")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(trust) {
		return errors.New("SCEP trust unavailable")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: dns}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+address+"/scep/"+url.PathEscape(provisioner)+"?operation=GetCACert", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("local SCEP unavailable")
	}
	defer func() { _ = response.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 || response.StatusCode != http.StatusOK {
		return errors.New("local SCEP certificate response unavailable")
	}
	return verifySCEPDecrypter(raw, expected, time.Now())
}
func verifySCEPDecrypter(raw, expected []byte, now time.Time) error {
	block, _ := pem.Decode(expected)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("adopted decrypter unavailable")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) || cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		return errors.New("adopted decrypter is not currently valid for encryption")
	}
	// GetCACert can return one DER certificate or a degenerate CMS certificate set.
	if bytes.Equal(raw, cert.Raw) {
		return nil
	}
	var outer struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"`
	}
	rest, err := asn1.Unmarshal(raw, &outer)
	if err != nil || len(rest) != 0 || !outer.Type.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}) {
		return errors.New("invalid SCEP certificate set")
	}
	var signed asn1.RawValue
	rest, err = asn1.Unmarshal(outer.Content.Bytes, &signed)
	if err != nil || len(rest) != 0 || signed.Tag != asn1.TagSequence || signed.Class != 0 {
		return errors.New("invalid SCEP signed data")
	}
	remaining := signed.Bytes
	field := 0
	for len(remaining) > 0 {
		var value asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &value)
		if err != nil {
			return errors.New("invalid SCEP certificate field")
		}
		if field >= 3 && value.Class == 2 && value.Tag == 0 {
			certs := value.Bytes
			for len(certs) > 0 {
				var item asn1.RawValue
				certs, err = asn1.Unmarshal(certs, &item)
				if err != nil {
					return errors.New("invalid SCEP certificate encoding")
				}
				if bytes.Equal(item.FullBytes, cert.Raw) {
					return nil
				}
			}
		}
		field++
	}
	return errors.New("live SCEP handler does not advertise adopted decrypter")
}
