package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Test-only in-memory wire response; no listener, socket or live authority runs.
type pureRoundTrip func(*http.Request) (*http.Response, error)

func (f pureRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type trackedBody struct {
	io.Reader
	closed bool
}

func (b *trackedBody) Close() error { b.closed = true; return nil }
func TestCAHTTPExecutesExactRequestClosesAndBoundsActualReader(t *testing.T) {
	request, e := http.NewRequest(http.MethodPost, "https://rsa.task11.test:8444/scep/wifi-scep?operation=PKIOperation", strings.NewReader("opaque signed CSR"))
	if e != nil {
		t.Fatal(e)
	}
	body := &trackedBody{Reader: strings.NewReader(strings.Repeat("x", 32768))}
	called := false
	client := &http.Client{Transport: pureRoundTrip(func(r *http.Request) (*http.Response, error) {
		called = true
		if r.Method != request.Method || r.URL.String() != request.URL.String() {
			t.Fatal("fixed client wire was rewritten")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/x-pki-message"}}, Body: body}, nil
	})}
	status, media, raw, e := performCAHTTP(context.Background(), client, request, 32768)
	if e != nil || !called || !body.closed || status != 200 || media != "application/x-pki-message" || len(raw) != 32768 {
		t.Fatal("exact bounded wire request/response missing")
	}
	for _, bad := range []io.Reader{strings.NewReader(strings.Repeat("x", 32769)), brokenReader{}} {
		responseBody := &trackedBody{Reader: bad}
		client.Transport = pureRoundTrip(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: responseBody}, nil
		})
		if _, _, raw, e := performCAHTTP(context.Background(), client, request, 32768); e == nil || raw != nil || !responseBody.closed {
			t.Fatal("incomplete/oversized CA response retained or body leaked")
		}
	}
}
func TestIssuedCertificateBodyUsesOnlyActualPublicDER(t *testing.T) {
	f := pureSCEPFixture(t)
	body, e := issuedCertificateBody(f.issued)
	if e != nil {
		t.Fatal(e)
	}
	public, e := x509.MarshalPKIXPublicKey(f.issued.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(body.LeafDER, f.issued.Raw) || body.LeafDERSHA256 != digestBytes(f.issued.Raw) || body.PublicKeySHA256 != digestBytes(public) || body.Serial != f.issued.SerialNumber.String() || !body.NotBefore.Equal(f.issued.NotBefore) || !body.NotAfter.Equal(f.issued.NotAfter) || body.Subject != f.issued.Subject.String() || !body.ClientAuthOnly {
		t.Fatal("issued metadata reconstructed without actual DER")
	}
	if _, e := issuedCertificateBody(nil); e == nil {
		t.Fatal("missing genuine leaf projected")
	}
	// Mutating the returned public bytes must not mutate the authenticated leaf.
	body.LeafDER[0] ^= 1
	if bytes.Equal(body.LeafDER, f.issued.Raw) {
		t.Fatal("issued DER aliases authenticated certificate")
	}
}
