package stepca

import (
	"context"
	"crypto/x509"
	"testing"
	"time"
)

func TestServerProfileCacheRenewalAndReadOutage(t *testing.T) {
	m, s, key := fixture(t)
	ca, e := m.Ensure(context.Background(), definition(), key)
	if e != nil {
		t.Fatal(e)
	}
	b := ServerBackend{Store: s, Gate: m.Gate, Signer: key, CA: ca, DNSName: "radius.example.test", CertificateSecret: "server-cert", KeySecret: "server-key", Now: time.Now}
	first, e := b.Renew(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	c, e := parseCert(first.Certificate)
	if e != nil {
		t.Fatal(e)
	}
	if c.IsCA || len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(c.DNSNames) != 1 || c.DNSNames[0] != b.DNSName {
		t.Fatal("server profile differs")
	}
	s.writes = nil
	second, e := b.Renew(context.Background())
	if e != nil || string(first.Certificate) != string(second.Certificate) || len(s.writes) != 0 {
		t.Fatal("compatible cache replaced", e)
	}
	s.readError = true
	if _, e = b.Renew(context.Background()); e == nil || len(s.writes) != 0 {
		t.Fatal("read outage reissued")
	}
	s.readError = false
	b.Now = func() time.Time { return time.Now().Add(70 * 24 * time.Hour) }
	third, e := b.Renew(context.Background())
	if e != nil || string(third.Certificate) == string(first.Certificate) {
		t.Fatal("near expiry not renewed", e)
	}
}

func TestMalformedServerCacheNeverTriggersReplacement(t *testing.T) {
	m, s, key := fixture(t)
	ca, err := m.Ensure(context.Background(), definition(), key)
	if err != nil {
		t.Fatal(err)
	}
	backend := ServerBackend{Store: s, Gate: m.Gate, Signer: key, CA: ca, DNSName: "radius.example.test", CertificateSecret: "server-cert", KeySecret: "server-key"}
	if _, err = backend.Renew(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.values["server-cert"] = []byte("malformed")
	s.writes = nil
	if _, err = backend.Renew(context.Background()); err == nil || len(s.writes) != 0 {
		t.Fatal("replaced malformed server identity", err)
	}
}

func TestLocalServerCacheAdoptionAndMalformedRefusal(t *testing.T) {
	manager, store, key := fixture(t)
	ca, err := manager.Ensure(context.Background(), definition(), key)
	if err != nil {
		t.Fatal(err)
	}
	b := ServerBackend{Store: store, Gate: manager.Gate, Signer: key, CA: ca, DNSName: "radius.example.test", CertificateSecret: "server-cert", KeySecret: "server-key"}
	original, err := b.Renew(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	delete(store.values, "server-cert")
	delete(store.values, "server-key")
	store.writes = nil
	b.LocalCache = ServerCertificate{Certificate: original.Chain, Key: original.Key}
	got, err := b.Renew(context.Background())
	if err != nil || string(got.Certificate) != string(original.Certificate) {
		t.Fatal("local cache was not adopted", err)
	}
	b.LocalCache.Key = []byte("malformed")
	store.writes = nil
	if _, err = b.Renew(context.Background()); err == nil || len(store.writes) != 0 {
		t.Fatal("malformed local cache replaced")
	}
}
