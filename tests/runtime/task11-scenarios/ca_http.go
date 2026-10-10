package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"net/http"

	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

// The live caller supplies only clients/requests built by the fixed pinned
// constructors. No client, endpoint or transport can enter from private stdin.
func performCAHTTP(ctx context.Context, client *http.Client, request *http.Request, limit int) (int, string, []byte, error) {
	if ctx == nil || client == nil || request == nil || request.URL == nil || request.URL.Scheme != "https" || limit < 1 || limit > 32<<10 {
		return 0, "", nil, errors.New("bounded fixed HTTPS exchange required")
	}
	response, e := client.Do(request.WithContext(ctx))
	if e != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return 0, "", nil, errors.New("fixed CA HTTP transport unavailable")
	}
	if response == nil || response.Body == nil {
		return 0, "", nil, errors.New("fixed CA HTTP response unavailable")
	}
	body, readErr := readClientBody(response.Body, limit)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		clear(body)
		return response.StatusCode, "", nil, errors.New("CA HTTP body incomplete or unretired")
	}
	return response.StatusCode, response.Header.Get("Content-Type"), body, nil
}
func issuedCertificateBody(certificate *x509.Certificate) (*scenariocontract.IssuedCertificate, error) {
	if certificate == nil || len(certificate.Raw) == 0 || len(certificate.Raw) > 32<<10 {
		return nil, errors.New("actual bounded public issued DER required")
	}
	leaf, e := x509.ParseCertificate(certificate.Raw)
	if e != nil || leaf.IsCA || leaf.SerialNumber.Sign() <= 0 || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(leaf.UnknownExtKeyUsage) != 0 {
		return nil, errors.New("actual client-only issued DER required")
	}
	public, e := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if e != nil {
		return nil, errors.New("actual issued public key unavailable")
	}
	return &scenariocontract.IssuedCertificate{Serial: leaf.SerialNumber.String(), LeafDER: bytes.Clone(leaf.Raw), LeafDERSHA256: digestBytes(leaf.Raw), PublicKeySHA256: digestBytes(public), NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Subject: leaf.Subject.String(), ClientAuthOnly: true}, nil
}
