package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"
)

func TestClosedCAPhaseMapAndOriginalMatcherStaySeparate(t *testing.T) {
	for _, original := range []string{"10.203.11.31", "10.203.11.32"} {
		for _, phase := range []string{"original", "adopted", "passive"} {
			actual, e := phaseCAPeer(original, phase)
			if e != nil {
				t.Fatal(e)
			}
			expected := original
			if phase != "original" {
				if original == "10.203.11.31" {
					expected = "10.203.11.21"
				} else {
					expected = "10.203.11.22"
				}
			}
			if actual != expected {
				t.Fatal("phase selected a foreign node")
			}
		}
	}
	for _, pair := range [][2]string{{"10.203.11.21", "original"}, {"10.203.11.31", "unknown"}, {"127.0.0.1", "adopted"}} {
		if _, e := phaseCAPeer(pair[0], pair[1]); e == nil {
			t.Fatal("unknown phase/foreign original accepted")
		}
	}
	p := pureNASPlan().RSA
	p.Blue = "10.203.11.21"
	if validateCAClientPlan(p) == nil {
		t.Fatal("original-blue assertion relaxed by phase support")
	}
}
func TestPhaseRSAClientPreservesActualPinnedTLSAndRoutes(t *testing.T) {
	root := pureTrustPEM(t, true, "rsa.task11.test")
	broker := pureTrustPEM(t, false, "localhost")
	p := pureNASPlan().RSA
	p.RootSHA256 = digestBytes(root)
	p.BrokerCertificateSHA256 = digestBytes(broker)
	for _, phase := range []string{"original", "adopted", "passive"} {
		for _, isBroker := range []bool{false, true} {
			client, e := pinnedPhaseRSAClient(p, phase, root, broker, isBroker, nil)
			if e != nil {
				t.Fatal(e)
			}
			if client == nil {
				t.Fatal("fixed client missing")
			}
			tr, ok := client.Transport.(*http.Transport)
			if !ok || tr.TLSClientConfig == nil || tr.DialContext == nil {
				t.Fatal("actual phase transport missing")
			}
			trust, name := root, p.DNS
			if isBroker {
				trust, name = broker, "localhost"
			}
			expected := x509.NewCertPool()
			if !expected.AppendCertsFromPEM(trust) {
				t.Fatal("pure trust invalid")
			}
			cfg := tr.TLSClientConfig
			if cfg.InsecureSkipVerify || cfg.MinVersion < tls.VersionTLS12 || cfg.ServerName != name || cfg.RootCAs == nil || !cfg.RootCAs.Equal(expected) || tr.Proxy != nil || client.CheckRedirect == nil {
				t.Fatal("phase replaced original trust/TLS")
			}
			// All attempted pure-test addresses deliberately violate the allowlist:
			// this proves synchronous refusal without any socket/network execution.
			if _, e := tr.DialContext(context.Background(), "tcp4", "other.task11.test:8444"); e == nil {
				t.Fatal("foreign phase destination accepted")
			}
		}
	}
	if _, e := pinnedPhaseRSAClient(p, "unknown", root, broker, false, nil); e == nil {
		t.Fatal("unknown phase client created")
	}
}
