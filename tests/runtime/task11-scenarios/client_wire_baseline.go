package main

import (
	"bytes"
	"context"
	"crypto/md5" // #nosec G501 -- RADIUS request authenticators use mandated MD5.
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting"
	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
)

func digestBytes(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func wireAttribute(kind byte, value []byte) ([]byte, error) {
	if len(value) > 253 {
		return nil, errors.New("RADIUS attribute exceeds protocol bound")
	}
	return append([]byte{kind, byte(len(value) + 2)}, value...), nil
}
func makeAccountingRequest(p scenarioPlan, event plannedEvent, station, token string, secret []byte, id byte) ([]byte, error) {
	if err := validatePlan(p); err != nil {
		return nil, err
	}
	chosen := false
	for _, e := range p.Events {
		if e == event {
			chosen = true
		}
	}
	if !chosen || len(secret) < 8 || len(secret) > 253 || !bytes.HasPrefix(secret, []byte("task11-")) || strings.ContainsAny(string(secret), "\x00\r\n") || !strings.HasPrefix(token, binding.Prefix) || len(token) > 253 {
		return nil, errors.New("independent planned event/synthetic NAS inputs required")
	}
	one := func(v string) accounting.Attribute { return accounting.Attribute{Value: v, Count: 1} }
	if _, err := accounting.CanonicalKey(accounting.Raw{SourceIP: p.NAS, NASIP: one(p.NAS), Station: one(station), Session: one(p.Session)}); err != nil {
		return nil, errors.New("fixed NAS/session/station required")
	}
	packet := make([]byte, 20)
	packet[0] = 4
	packet[1] = id
	text := []struct {
		kind  byte
		value []byte
	}{{4, []byte{10, 203, 11, 40}}, {31, []byte(station)}, {44, []byte(p.Session)}, {25, []byte(token)}}
	for _, a := range text {
		v, err := wireAttribute(a.kind, a.value)
		if err != nil {
			return nil, err
		}
		packet = append(packet, v...)
	}
	words := []struct {
		kind  byte
		value uint32
	}{{40, uint32(event.Status)}, {46, event.Duration}, {42, uint32(event.Upload & 0xffffffff)}, {43, uint32(event.Download & 0xffffffff)}, {52, uint32(event.Upload >> 32)}, {53, uint32(event.Download >> 32)}}
	for _, a := range words {
		v := make([]byte, 4)
		binary.BigEndian.PutUint32(v, a.value)
		attr, _ := wireAttribute(a.kind, v)
		packet = append(packet, attr...)
	}
	if len(packet) > 4096 {
		return nil, errors.New("bounded accounting packet exceeded")
	}
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	signed := append(append([]byte(nil), packet...), secret...)
	sum := md5.Sum(signed) // #nosec G401 -- RFC2866 Accounting-Request authenticator.
	clear(signed)
	copy(packet[4:20], sum[:])
	return packet, nil
}
func parseAttributes(wire []byte) (map[byte][][]byte, error) {
	if len(wire) > 4076 {
		return nil, errors.New("RADIUS attributes exceed packet bound")
	}
	attrs := map[byte][][]byte{}
	for at := 0; at < len(wire); {
		if at+2 > len(wire) || wire[at+1] < 2 || at+int(wire[at+1]) > len(wire) {
			return nil, errors.New("malformed RADIUS attribute")
		}
		end := at + int(wire[at+1])
		attrs[wire[at]] = append(attrs[wire[at]], wire[at+2:end])
		at = end
	}
	return attrs, nil
}
func readClientBody(r io.Reader, limit int) ([]byte, error) {
	if r == nil || limit < 1 || limit > 1<<20 {
		return nil, errors.New("bounded client response required")
	}
	body, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil || len(body) > limit {
		clear(body)
		return nil, errors.New("client response incomplete or oversized")
	}
	return body, nil
}
func singlePinnedCertificate(data []byte, pin string) (*x509.Certificate, error) {
	if len(data) > 64<<10 || !shaPattern.MatchString(pin) || digestBytes(data) != pin {
		return nil, errors.New("original TLS certificate pin differs")
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("single exact original TLS certificate required")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("original TLS certificate invalid")
	}
	return cert, nil
}

// This constructor is the original RSA SCEP/broker client, never an endpoint
// override for shipping step-ca's SDK. EC mTLS renewal has its own fixed8443 path.
func pinnedCAClient(p caClientPlan, rootPEM, brokerPEM []byte, broker bool, certificate *tls.Certificate) (*http.Client, error) {
	return rsaClientForPhase(p, "original", rootPEM, brokerPEM, broker, certificate)
}
func rsaClientForPhase(p caClientPlan, phase string, rootPEM, brokerPEM []byte, broker bool, certificate *tls.Certificate) (*http.Client, error) {
	if err := validateCAClientPlan(p); err != nil {
		return nil, err
	}
	peer, err := phaseCAPeer(p.Blue, phase)
	if err != nil {
		return nil, err
	}
	root, err := singlePinnedCertificate(rootPEM, p.RootSHA256)
	if err != nil || !root.IsCA {
		return nil, errors.New("pinned original CA root required")
	}
	trust := root
	name := p.DNS
	port := 8444
	if broker {
		trust, err = singlePinnedCertificate(brokerPEM, p.BrokerCertificateSHA256)
		if err != nil || trust.IsCA || trust.VerifyHostname("localhost") != nil {
			return nil, errors.New("pinned original loopback broker identity required")
		}
		name = "localhost"
		port = 9081
	}
	roots := x509.NewCertPool()
	roots.AddCert(trust)
	cfg := &tls.Config{RootCAs: roots, ServerName: name, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13}
	if certificate != nil {
		if certificate.PrivateKey == nil || len(certificate.Certificate) == 0 {
			return nil, errors.New("original client mTLS pair unavailable")
		}
		pair := *certificate
		pair.Certificate = make([][]byte, len(certificate.Certificate))
		for i, v := range certificate.Certificate {
			pair.Certificate[i] = bytes.Clone(v)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	target := net.JoinHostPort(peer, strconv.Itoa(port))
	expected := net.JoinHostPort(p.DNS, strconv.Itoa(port))
	if broker {
		expected = net.JoinHostPort("localhost", strconv.Itoa(port))
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("10.203.11.40")}}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: cfg, DisableKeepAlives: true, MaxConnsPerHost: 1, ResponseHeaderTimeout: 4 * time.Second, MaxResponseHeaderBytes: 32 << 10, ForceAttemptHTTP2: false, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if (network != "tcp" && network != "tcp4") || address != expected {
			return nil, errors.New("CA client destination outside fixed private authority")
		}
		return dialer.DialContext(ctx, "tcp4", target)
	}}
	return &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
