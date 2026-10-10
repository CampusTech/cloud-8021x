package stepca

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

func TestAdoptOnlyNeverInitializesOrWrites(t *testing.T) {
	for _, mode := range []string{"empty", "partial", "list-error", "read-error", "wrong-key", "adopt"} {
		t.Run(mode, func(t *testing.T) {
			m, s, key := fixture(t)
			original, err := m.Ensure(context.Background(), definition(), key)
			if err != nil {
				t.Fatal(err)
			}
			s.writes = nil
			switch mode {
			case "empty":
				s.values = map[string][]byte{}
			case "partial":
				delete(s.values, "intermediate")
			case "list-error":
				s.listError = true
			case "read-error":
				s.readError = true
			case "wrong-key":
				key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			}
			got, err := Adopt(context.Background(), s, definition(), key.Public(), time.Now())
			if (err == nil) != (mode == "adopt") {
				t.Fatalf("mode %s: %v", mode, err)
			}
			if len(s.writes) != 0 {
				t.Fatal("read-only adoption wrote CA material")
			}
			if mode == "adopt" && (!bytes.Equal(got.Root, original.Root) || !bytes.Equal(got.DecrypterKey, original.DecrypterKey)) {
				t.Fatal("identity changed")
			}
		})
	}
}
func TestAdoptServerRequiresExistingExactPair(t *testing.T) {
	m, s, key := fixture(t)
	material, err := m.Ensure(context.Background(), definition(), key)
	if err != nil {
		t.Fatal(err)
	}
	b := &ServerBackend{Store: s, Gate: m.Gate, Signer: key, CA: material, DNSName: "radius.example.test", CertificateSecret: "server", KeySecret: "server-key"}
	original, err := b.Renew(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"adopt", "missing-key", "wrong-name", "read-error"} {
		t.Run(mode, func(t *testing.T) {
			s.writes = nil
			s.readError = mode == "read-error"
			s.values["server-key"] = original.Key
			dns := b.DNSName
			if mode == "missing-key" {
				delete(s.values, "server-key")
			}
			if mode == "wrong-name" {
				dns = "other.example.test"
			}
			got, err := AdoptServer(context.Background(), s, material, dns, "server", "server-key", time.Now())
			if (err == nil) != (mode == "adopt") {
				t.Fatalf("%s: %v", mode, err)
			}
			if len(s.writes) != 0 {
				t.Fatal("adoption renewed server certificate")
			}
			if mode == "adopt" && !bytes.Equal(got.Certificate, original.Certificate) {
				t.Fatal("server identity changed")
			}
		})
	}
}

func TestAdoptedConfigRejectsChangedIdentityAndTrailingJSON(t *testing.T) {
	expected := []byte(`{"key":"original-version","db":{"dataSource":"original-CA"}}`)
	if err := ValidateAdoptedConfig([]byte(" { \"key\":\"original-version\",\"db\":{\"dataSource\":\"original-CA\"} } "), expected); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{"key":"replacement","db":{"dataSource":"original-CA"}}`, `{"key":"original-version","db":{"dataSource":"other-CA"}}`, `{"key":"original-version","db":{"dataSource":"original-CA"}} {}`} {
		if ValidateAdoptedConfig([]byte(raw), expected) == nil {
			t.Fatal("changed or ambiguous CA identity accepted")
		}
	}
}
