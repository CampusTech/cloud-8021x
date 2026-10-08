package native

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthenticatedReadinessRequiresPolicyTrustAndFreshProof(t *testing.T) {
	secret := []byte(strings.Repeat("s", 32))
	expected := Readiness{ConfigSHA256: strings.Repeat("a", 64), TrustSHA256: strings.Repeat("b", 64), ServerDNS: "radius.fixture", Ready: true}
	for _, mode := range []string{"valid", "policy", "trust", "unready", "wrong-key"} {
		t.Run(mode, func(t *testing.T) {
			local := expected
			key := secret
			switch mode {
			case "policy":
				local.ConfigSHA256 = strings.Repeat("c", 64)
			case "trust":
				local.TrustSHA256 = strings.Repeat("c", 64)
			case "unready":
				local.Ready = false
			case "wrong-key":
				key = []byte(strings.Repeat("x", 32))
			}
			srv := httptest.NewServer(ReadinessHandler(key, []string{"127.0.0.1"}, func(context.Context) (Readiness, error) { return local, nil }))
			defer srv.Close()
			e := ProbeReadiness(context.Background(), srv.URL, secret, expected)
			if (e == nil) != (mode == "valid") {
				t.Fatalf("%s %v", mode, e)
			}
		})
	}
}
