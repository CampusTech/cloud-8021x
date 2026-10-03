// Package server is the HTTP surface. It reads the raw body, verifies the
// step-ca caller, parses the request, extracts the device identity, and
// asks the Decider. Any failure along the way responds allow=false: the
// handler is fail-closed by construction.
package server

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/CampusTech/cloud-8021x/webhook/internal/challenge"

	"github.com/CampusTech/cloud-8021x/webhook/internal/signature"
	"github.com/CampusTech/cloud-8021x/webhook/internal/types"
	"github.com/sirupsen/logrus"
)

// Decider decides allow/deny for a device serial.
type Decider interface {
	Allow(serial string) bool
}

type DeciderFunc func(serial string) bool

func (f DeciderFunc) Allow(serial string) bool { return f(serial) }

// ResponseShape is the JSON we return (mirrors types.ResponseBody).
type ResponseShape struct {
	Allow bool `json:"allow"`
}

type handler struct {
	secret               []byte
	scepSigningKey       []byte
	decider              Decider
	mutualTLS            bool
	inventoryProvisioner string
}

// New returns an http.Handler serving POST /authorize, POST /scep-challenge,
// and GET /healthz. scepSigningKey verifies identity-bound challenge tokens;
// an absent or short key makes /scep-challenge deny every request.
func New(signingSecret, scepSigningKey string, d Decider) http.Handler {
	h := &handler{secret: []byte(signingSecret), scepSigningKey: []byte(scepSigningKey), decider: d}
	return h.routes()
}

func (h *handler) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", h.authorize)
	mux.HandleFunc("/scep-challenge", h.scepChallengeHandler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

func deny(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // step-ca reads the body; allow=false denies
	_ = json.NewEncoder(w).Encode(ResponseShape{Allow: false})
}

func allow(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(ResponseShape{Allow: true})
}

func (h *handler) authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		deny(w)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		logrus.WithError(err).Warn("deny: body read failed")
		deny(w)
		return
	}
	if !h.authenticated(r, body) {
		logrus.Warn("deny: invalid webhook authentication")
		deny(w)
		return
	}
	var req types.RequestBody
	if err := json.Unmarshal(body, &req); err != nil {
		logrus.WithError(err).Warn("deny: malformed body")
		deny(w)
		return
	}
	serial := ""
	if req.AttestationData != nil {
		serial = req.AttestationData.PermanentIdentifier
	}
	if h.decider.Allow(serial) {
		allow(w)
		return
	}
	deny(w)
}

// scepChallengeHandler serves step-ca's SCEP SCEPCHALLENGE webhook. It enforces
// an expiring challenge bound to the CSR identity and exact provisioner, then
// checks current device enrollment. Fail-closed at every step.
func (h *handler) scepChallengeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		deny(w)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		logrus.WithError(err).Warn("deny: body read failed")
		deny(w)
		return
	}
	if !h.authenticated(r, body) {
		logrus.Warn("deny: invalid webhook authentication")
		deny(w)
		return
	}
	var req types.RequestBody
	if err := json.Unmarshal(body, &req); err != nil {
		logrus.WithError(err).Warn("deny: malformed body")
		deny(w)
		return
	}
	if req.X509CertificateRequest == nil {
		logrus.Warn("deny: missing CSR")
		deny(w)
		return
	}
	if h.inventoryProvisioner != "" && req.ProvisionerName == h.inventoryProvisioner && challenge.VerifyInventory(h.scepSigningKey, req.SCEPChallenge, h.inventoryProvisioner, time.Now()) {
		allow(w)
		return
	}
	identity := challenge.NormalizeIdentity(req.X509CertificateRequest.Subject.CommonName)
	if !challenge.Verify(h.scepSigningKey, req.SCEPChallenge, req.X509CertificateRequest.Subject.CommonName, req.ProvisionerName, time.Now()) {
		logrus.Warn("deny: invalid or expired identity-bound SCEP challenge")
		deny(w)
		return
	}
	if h.decider.Allow(identity) {
		allow(w)
		return
	}
	deny(w)
}

func (h *handler) authenticated(r *http.Request, body []byte) bool {
	if h.mutualTLS {
		return r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.VerifiedChains[0]) > 0
	}
	return signature.Verify(h.secret, body, r.Header.Get("X-Smallstep-Signature"))
}
