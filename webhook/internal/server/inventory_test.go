package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/webhook/internal/challenge"
)

func TestInventoryChallengeRequiresModeProvisionerAndMTLS(t *testing.T) {
	token, err := challenge.IssueInventory([]byte(challengeKey), "wifi-scep", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	denyEnrollment := DeciderFunc(func(string) bool { return false })
	for _, tc := range []struct {
		name                  string
		handler               http.Handler
		identity, provisioner string
		authenticated, want   bool
	}{
		{"arbitrary CSR identity", NewMutualTLSInventory(challengeKey, "wifi-scep", denyEnrollment), "invented-staff", "wifi-scep", true, true},
		{"empty CSR identity", NewMutualTLSInventory(challengeKey, "wifi-scep", denyEnrollment), "", "wifi-scep", true, true},
		{"mode disabled", NewMutualTLS(challengeKey, denyEnrollment), "invented-staff", "wifi-scep", true, false},
		{"wrong provisioner", NewMutualTLSInventory(challengeKey, "wifi-scep", denyEnrollment), "invented-staff", "other", true, false},
		{"wrong configured provisioner", NewMutualTLSInventory(challengeKey, "other", denyEnrollment), "invented-staff", "wifi-scep", true, false},
		{"no client TLS", NewMutualTLSInventory(challengeKey, "wifi-scep", denyEnrollment), "invented-staff", "wifi-scep", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := scepBody(t, tc.identity, token, tc.provisioner)
			req := httptest.NewRequest("POST", "/scep-challenge", strings.NewReader(body))
			if tc.authenticated {
				req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}
			}
			w := httptest.NewRecorder()
			tc.handler.ServeHTTP(w, req)
			var result ResponseShape
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Allow != tc.want {
				t.Fatalf("allow=%v want=%v", result.Allow, tc.want)
			}
		})
	}
}
