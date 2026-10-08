package host

import (
	"strings"
	"testing"
)

func TestMetadataIsolationRetainsDNSOnly(t *testing.T) {
	if _, e := MetadataRules(0); e == nil {
		t.Fatal("root isolation accepted")
	}
	b, e := MetadataRules(1042)
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{"169.254.169.254", "fd20:ce::254", "::ffff:169.254.169.254", "meta skuid 1042", "udp dport 53 accept", "tcp dport 53 accept"} {
		if !strings.Contains(string(b), s) {
			t.Fatal(s)
		}
	}
	if strings.Contains(string(b), "dport 80 accept") || strings.Contains(string(b), "dport 443 accept") {
		t.Fatal("metadata bypass")
	}
}
