// Package server is the HTTP surface. It reads the raw body, verifies the
// step-ca HMAC signature, parses the request, extracts the device serial, and
// asks the Decider. Any failure along the way responds allow=false: the
// handler is fail-closed by construction.
package server

import (
	"encoding/json"
	"io"
	"net/http"

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
	secret  []byte
	decider Decider
}

// New returns an http.Handler serving POST /authorize and GET /healthz.
func New(signingSecret string, d Decider) http.Handler {
	h := &handler{secret: []byte(signingSecret), decider: d}
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", h.authorize)
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
