package main

import (
	"errors"
	"mime"
	"net/http"
	"strings"
)

// The genuine broker returns an opaque plain-text challenge, not JSON. Client
// receipt over pinned TLS does not authenticate its MAC; the actual authority
// verifies it. Never copy the authority challenge signing key into NAS.
func brokerChallengeReply(status int, contentType string, body []byte) (string, error) {
	media, parameters, err := mime.ParseMediaType(contentType)
	if err != nil || status != http.StatusOK || media != "text/plain" || len(parameters) > 1 || len(body) == 0 || len(body) > 4096 {
		return "", errors.New("bounded genuine broker plaintext response required")
	}
	for name, value := range parameters {
		if name != "charset" || !strings.EqualFold(value, "utf-8") {
			return "", errors.New("unsupported broker response media parameters")
		}
	}
	for _, v := range body {
		if v < 33 || v > 126 {
			return "", errors.New("broker challenge has unsupported bytes")
		}
	}
	return string(body), nil
}
