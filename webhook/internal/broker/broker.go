// Package broker implements Fleet's native Smallstep dynamic challenge protocol.
// This public HTTPS listener is separate from step-ca's loopback mTLS webhook.
package broker

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/webhook/internal/challenge"
)

type Options struct {
	Username    string
	Token       string // Fleet Smallstep password, not a bearer header
	SigningKey  string
	SCEPURL     string
	Provisioner string
}

func (o Options) Validate() error {
	if strings.TrimSpace(o.Username) == "" || strings.ContainsAny(o.Username, ":\r\n") || len(o.Token) < 32 || len(o.SigningKey) < challenge.MinKeyBytes {
		return errors.New("SCEP broker requires a username and credentials of at least 32 bytes")
	}
	u, err := url.Parse(o.SCEPURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/scep/"+o.Provisioner || strings.TrimSpace(o.Provisioner) == "" || len(o.Provisioner) > 256 || strings.ContainsAny(o.Provisioner, "/?#\r\n") {
		return errors.New("SCEP broker requires an HTTPS server URL matching /scep/<provisioner>")
	}
	return nil
}

type request struct {
	Webhook struct {
		WebhookEvent   string `json:"webhookEvent"`
		ID             int    `json:"id"`
		EventTimestamp int64  `json:"eventTimestamp"`
		Name           string `json:"name"`
	} `json:"webhook"`
	Event struct {
		SCEPServerURL     string          `json:"scepServerUrl"`
		PayloadIdentifier string          `json:"payloadIdentifier"`
		PayloadTypes      []string        `json:"payloadTypes"`
		Device            json.RawMessage `json:"device,omitempty"`
	} `json:"event"`
}

// New returns only the Fleet challenge and health routes. Caller must enable it
// exclusively with certificate-inventory authorization and serve it over HTTPS.
func New(o Options) (http.Handler, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	expectedUser := sha256.Sum256([]byte(o.Username))
	expectedToken := sha256.Sum256([]byte(o.Token))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("POST /fleet/scep-challenge", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		username, password, ok := r.BasicAuth()
		actualUser := sha256.Sum256([]byte(username))
		actualToken := sha256.Sum256([]byte(password))
		matches := subtle.ConstantTimeCompare(actualUser[:], expectedUser[:]) & subtle.ConstantTimeCompare(actualToken[:], expectedToken[:])
		if !ok || matches != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			http.Error(w, "expected JSON", http.StatusUnsupportedMediaType)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			} else {
				http.Error(w, "invalid request", http.StatusBadRequest)
			}
			return
		}
		var req request
		decoder := json.NewDecoder(strings.NewReader(string(body)))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&req) != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		var trailing any
		if decoder.Decode(&trailing) != io.EOF || req.Webhook.WebhookEvent != "SCEPChallenge" || req.Event.SCEPServerURL != o.SCEPURL || len(req.Event.PayloadIdentifier) > 1024 || len(req.Event.PayloadTypes) != 1 || req.Event.PayloadTypes[0] != "com.apple.security.scep" {
			http.Error(w, "invalid SCEP event", http.StatusBadRequest)
			return
		}
		// Fleet generates payloadIdentifier randomly and omits device on configuration
		// probes. Neither is a trusted device identity or an authorization input.
		token, err := challenge.IssueInventory([]byte(o.SigningKey), o.Provisioner, time.Now())
		if err != nil {
			http.Error(w, "challenge unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, token)
	})
	return mux, nil
}
