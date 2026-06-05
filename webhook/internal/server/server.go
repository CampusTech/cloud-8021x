// Package server is the HTTP surface. It reads the raw body, verifies the
// step-ca HMAC signature, parses the request, extracts the device serial, and
// asks the Decider. Any failure along the way responds allow=false: the
// handler is fail-closed by construction.
package server

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"

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
	secret        []byte
	scepChallenge []byte
	decider       Decider
}

// New returns an http.Handler serving POST /authorize, POST /scep-challenge,
// and GET /healthz. scepChallenge is the shared SCEP challenge value; when
// empty, /scep-challenge denies every request (fail-closed misconfiguration).
func New(signingSecret, scepChallenge string, d Decider) http.Handler {
	h := &handler{secret: []byte(signingSecret), scepChallenge: []byte(scepChallenge), decider: d}
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
	if !signature.Verify(h.secret, body, r.Header.Get("X-Smallstep-Signature")) {
		logrus.Warn("deny: invalid or missing signature")
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
// BOTH the static shared challenge value AND that the serial in the CSR Subject
// CommonName is a Fleet-enrolled host. Fail-closed at every step.
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
	if !signature.Verify(h.secret, body, r.Header.Get("X-Smallstep-Signature")) {
		logrus.Warn("deny: invalid or missing signature")
		deny(w)
		return
	}
	var req types.RequestBody
	if err := json.Unmarshal(body, &req); err != nil {
		logrus.WithError(err).Warn("deny: malformed body")
		deny(w)
		return
	}
	if len(h.scepChallenge) == 0 {
		logrus.Warn("deny: scep challenge not configured")
		deny(w)
		return
	}
	if subtle.ConstantTimeCompare(h.scepChallenge, []byte(req.SCEPChallenge)) != 1 {
		logrus.Warn("deny: invalid scep challenge")
		deny(w)
		return
	}
	if req.X509CertificateRequest == nil {
		logrus.Warn("deny: missing CSR")
		deny(w)
		return
	}
	serial := strings.TrimSpace(req.X509CertificateRequest.Subject.CommonName)
	serial = strings.TrimSuffix(serial, " Campus WiFi")
	serial = strings.TrimSpace(serial)
	if serial == "" {
		logrus.Warn("deny: empty serial in CSR common name")
		deny(w)
		return
	}
	if h.decider.Allow(serial) {
		allow(w)
		return
	}
	deny(w)
}
