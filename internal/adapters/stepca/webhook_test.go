package stepca

import (
	"bytes"
	"testing"
	"time"
)

func TestWebhookLoopbackAdoptionAndPartialFailure(t *testing.T) {
	first, e := LoopbackTLS(ServerCertificate{}, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	c, e := parseCert(first.Certificate)
	if e != nil || c.IsCA || len(c.IPAddresses) != 1 || c.IPAddresses[0].String() != "127.0.0.1" || len(c.DNSNames) != 1 || c.DNSNames[0] != "localhost" {
		t.Fatal("unbounded webhook identity")
	}
	same, e := LoopbackTLS(first, time.Now())
	if e != nil || !bytes.Equal(first.Key, same.Key) {
		t.Fatal("healthy webhook identity changed")
	}
	for _, partial := range []ServerCertificate{{Certificate: first.Certificate}, {Key: first.Key}, {Certificate: []byte("broken"), Key: first.Key}} {
		if _, e := LoopbackTLS(partial, time.Now()); e == nil {
			t.Fatal("partial or invalid webhook silently replaced")
		}
	}
}
