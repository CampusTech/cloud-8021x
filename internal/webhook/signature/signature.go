// Package signature verifies step-ca's X-Smallstep-Signature header:
// hex-encoded HMAC-SHA256 of the raw request body, keyed by the shared
// webhook signing secret. Any malformed or mismatched signature returns
// false (fail-closed).
package signature

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Verify reports whether sigHex is a valid HMAC-SHA256 of body under secret.
func Verify(secret, body []byte, sigHex string) bool {
	want, err := hex.DecodeString(sigHex)
	if err != nil || len(want) == 0 {
		return false
	}
	m := hmac.New(sha256.New, secret)
	m.Write(body)
	return hmac.Equal(want, m.Sum(nil))
}
