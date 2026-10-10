package main

import (
	"bytes"
	"crypto/md5" // RADIUS request authenticator is protocol mandated.
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAccountingWireHasFixedNASAndChosenGigawords(t *testing.T) {
	p := fixturePlan()
	event := plannedEvent{Status: 3, Duration: 60, Upload: 1<<32 + 100, Download: 2<<32 + 200}
	p.Events[1] = event
	key, token := actualClassForPureTest(t, time.Unix(1800000000, 0))
	secret := []byte("task11-only-private-secret")
	req, err := makeAccountingRequest(p, event, "AA:BB:CC:DD:EE:FF", token, secret, 9)
	if err != nil {
		t.Fatal(err)
	}
	if len(req) < 20 || req[0] != 4 || req[1] != 9 || int(binary.BigEndian.Uint16(req[2:4])) != len(req) {
		t.Fatal("wrong accounting header")
	}
	check := bytes.Clone(req)
	clear(check[4:20])
	sum := md5.Sum(append(check, secret...))
	if !bytes.Equal(req[4:20], sum[:]) {
		t.Fatal("request authenticator differs from actual wire")
	}
	attrs, err := parseAttributes(req[20:])
	if err != nil {
		t.Fatal(err)
	}
	for typ, want := range map[byte]uint32{40: 3, 46: 60, 42: 100, 43: 200, 52: 1, 53: 2} {
		if len(attrs[typ]) != 1 || len(attrs[typ][0]) != 4 || binary.BigEndian.Uint32(attrs[typ][0]) != want {
			t.Fatalf("wrong independently chosen counter attribute%d", typ)
		}
	}
	if !bytes.Equal(attrs[4][0], []byte{10, 203, 11, 40}) || string(attrs[25][0]) != token || string(attrs[44][0]) != p.Session {
		t.Fatal("NAS/session/Class was rewritten")
	}
	_ = key // class verification occurs before accounting transmission, separately.
	ack := signedServerReply(t, req, secret, 5, nil)
	if _, err := validateResponse(ack, req, secret, 5); err != nil {
		t.Fatal(err)
	}
	bad := p
	bad.NAS = "10.203.11.41"
	if _, err := makeAccountingRequest(bad, event, "AA:BB:CC:DD:EE:FF", token, secret, 9); err == nil {
		t.Fatal("foreign NAS accounting packet created")
	}
	if _, err := parseAttributes([]byte{25, 1}); err == nil {
		t.Fatal("malformed attribute accepted")
	}
}

func TestClientBodyExactLimitAndOverflow(t *testing.T) {
	for _, n := range []int{32768, 32769} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			b, err := readClientBody(bytes.NewReader(bytes.Repeat([]byte("x"), n)), 32768)
			if n == 32768 && (err != nil || len(b) != n) {
				t.Fatalf("exact bounded body refused%d %v", len(b), err)
			}
			if n > 32768 && err == nil {
				t.Fatal("oversized actual io.Reader body accepted")
			}
		})
	}
	t.Run("partial-read", func(t *testing.T) {
		if _, err := readClientBody(io.MultiReader(bytes.NewReader([]byte("private")), brokenReader{}), 32768); err == nil {
			t.Fatal("partial read treated as complete")
		}
	})
}

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func pureTrustPEM(t *testing.T, ca bool, name string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	usage := x509.KeyUsageDigitalSignature
	if ca {
		usage |= x509.KeyUsageCertSign
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: ca, BasicConstraintsValid: true, KeyUsage: usage, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
func TestPinnedClientHasNoProxyOrTLSFallback(t *testing.T) {
	root := pureTrustPEM(t, true, "rsa.task11.test")
	broker := pureTrustPEM(t, false, "localhost")
	p := caClientPlan{Blue: "10.203.11.31", DNS: "rsa.task11.test", Provisioner: "wifi-scep", RootSHA256: digestBytes(root), IntermediateSHA256: strings.Repeat("b", 64), DecrypterSHA256: strings.Repeat("c", 64), BrokerCertificateSHA256: digestBytes(broker), BrokerTLSName: "localhost", BrokerTokenSHA256: strings.Repeat("e", 64)}
	for _, brokerClient := range []bool{false, true} {
		client, err := pinnedCAClient(p, root, broker, brokerClient, nil)
		if err != nil {
			t.Fatal(err)
		}
		if client == nil {
			t.Fatal("pinned client missing")
		}
		transport, ok := client.Transport.(*http.Transport)
		if !ok || transport.TLSClientConfig == nil {
			t.Fatal("fixed actual TLS transport missing")
		}
		cfg := transport.TLSClientConfig
		expectedRoots := x509.NewCertPool()
		trust := root
		if brokerClient {
			trust = broker
		}
		if !expectedRoots.AppendCertsFromPEM(trust) {
			t.Fatal("pure pinned trust invalid")
		}
		name := p.DNS
		if brokerClient {
			name = "localhost"
		}
		if transport.Proxy != nil || client.CheckRedirect == nil || cfg.InsecureSkipVerify || cfg.MinVersion < tls.VersionTLS12 || cfg.ServerName != name || cfg.RootCAs == nil || !cfg.RootCAs.Equal(expectedRoots) || client.Timeout > 5*time.Second || transport.DialContext == nil {
			t.Fatal("unsafe proxy/TLS/endpoint fallback")
		}
	}
	bad := p
	bad.RootSHA256 = hex.EncodeToString(bytes.Repeat([]byte{9}, 32))
	if _, err := pinnedCAClient(bad, root, broker, false, nil); err == nil {
		t.Fatal("changed original trust accepted")
	}
}
