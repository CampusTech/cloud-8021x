package migration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

type LegacyCertificateState struct {
	Version  int                              `json:"version"`
	Source   string                           `json:"source"`
	Trust    *string                          `json:"trust"`
	Hosts    map[string]LegacyCertificateHost `json:"hosts"`
	Commands []LegacyCommand                  `json:"commands"`
}
type LegacyCertificateHost struct {
	Binding       []json.RawMessage             `json:"binding"`
	LastAttempt   json.Number                   `json:"last_attempt"`
	Platform      string                        `json:"platform"`
	PollingExempt bool                          `json:"polling_exempt,omitempty"`
	Observation   *LegacyCertificateObservation `json:"observation,omitempty"`
}
type LegacyCertificateObservation struct {
	Fingerprints  []string               `json:"fingerprints"`
	ObservedAt    json.Number            `json:"observed_at"`
	TrustVerified bool                   `json:"trust_verified"`
	ExpiresAt     map[string]json.Number `json:"expires_at,omitempty"`
}
type LegacyCommand struct {
	UUID        string                       `json:"uuid"`
	CreatedAt   json.Number                  `json:"created_at"`
	Transport   string                       `json:"transport,omitempty"`
	ExecutionID string                       `json:"execution_id,omitempty"`
	Hosts       map[string][]json.RawMessage `json:"hosts"`
}

func originalTime(n json.Number) error {
	if n == "" {
		return errors.New("missing original timestamp")
	}
	_, e := ReceiptTime([]byte(n))
	return e
}
func DecodeCertificates(raw []byte) (LegacyCertificateState, error) {
	var c LegacyCertificateState
	if len(raw) > 16<<20 || domain.DecodeJSONStrict(raw, &c) != nil || c.Version != 1 || c.Hosts == nil || c.Commands == nil || len(c.Hosts) > 100000 || len(c.Commands) > 100000 {
		return c, errors.New("invalid legacy certificate state")
	}
	u, e := url.Parse(c.Source)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.HasSuffix(c.Source, "/") {
		return c, errors.New("invalid legacy Fleet source")
	}
	if c.Trust != nil && !digestPattern.MatchString(*c.Trust) {
		return c, errors.New("invalid legacy trust digest")
	}
	for uuid, h := range c.Hosts {
		if uuid == "" || len(uuid) > 253 || !slices.Contains([]string{"darwin", "ios", "ipados", "windows"}, h.Platform) || originalTime(h.LastAttempt) != nil {
			return c, errors.New("invalid legacy host")
		}
		if e := validateLegacyBinding(h.Binding, h.Platform); e != nil {
			return c, e
		}
		if o := h.Observation; o != nil {
			if originalTime(o.ObservedAt) != nil || o.Fingerprints == nil || len(o.Fingerprints) > 1024 {
				return c, errors.New("invalid legacy observation")
			}
			seen := map[string]bool{}
			for _, fp := range o.Fingerprints {
				if !digestPattern.MatchString(fp) || seen[fp] {
					return c, errors.New("invalid legacy fingerprint")
				}
				seen[fp] = true
			}
			for fp, at := range o.ExpiresAt {
				if !seen[fp] || originalTime(at) != nil {
					return c, errors.New("invalid legacy certificate expiry")
				}
			}
		}
	}
	seen := map[string]bool{}
	pending := map[string]int{}
	for _, cmd := range c.Commands {
		if cmd.UUID == "" || len(cmd.UUID) > 253 || seen[cmd.UUID] || originalTime(cmd.CreatedAt) != nil || len(cmd.Hosts) == 0 || len(cmd.Hosts) > 1000 || (cmd.Transport != "" && cmd.Transport != "windows_script") || len(cmd.ExecutionID) > 253 {
			return c, errors.New("invalid legacy command")
		}
		seen[cmd.UUID] = true
		if cmd.Transport == "windows_script" && len(cmd.Hosts) != 1 {
			return c, errors.New("ambiguous legacy script host")
		}
		for uuid, binding := range cmd.Hosts {
			h, ok := c.Hosts[uuid]
			if !ok {
				return c, errors.New("orphan legacy command")
			}
			if (cmd.Transport == "windows_script") != (h.Platform == "windows") {
				return c, errors.New("legacy command transport mismatch")
			}
			a, _ := json.Marshal(binding)
			b, _ := json.Marshal(h.Binding)
			if !bytes.Equal(a, b) {
				return c, errors.New("legacy command enrollment mismatch")
			}
			pending[uuid]++
			if pending[uuid] > 2 {
				return c, errors.New("legacy pending budget exceeded")
			}
		}
	}
	return c, nil
}
func validateLegacyBinding(b []json.RawMessage, platform string) error {
	n := 3
	if platform == "windows" {
		n = 4
	}
	if len(b) != n {
		return errors.New("invalid legacy enrollment binding")
	}
	var id uint64
	if json.Unmarshal(b[0], &id) != nil || id == 0 {
		return errors.New("invalid legacy host ID")
	}
	if _, e := ReceiptTime(b[1]); e != nil {
		return e
	}
	var enrolled *string
	if json.Unmarshal(b[2], &enrolled) != nil {
		return errors.New("invalid original Fleet enrollment")
	}
	if enrolled != nil {
		raw, _ := json.Marshal(*enrolled)
		if _, e := ReceiptTime(raw); e != nil {
			return e
		}
	}
	if n == 4 {
		var script string
		if json.Unmarshal(b[3], &script) != nil || !digestPattern.MatchString(script) {
			return errors.New("invalid original Windows script binding")
		}
	}
	return nil
}

// LegacyCollectionScope deliberately excludes unrecoverable RFC3339 spelling.
// It fences new submission until authenticated original-command evidence clears
// the imported reservation, regardless of a newly computed collection_key.
func LegacyCollectionScope(source string, id uint64, uuid string) string {
	sum := sha256.Sum256([]byte(strings.TrimSuffix(source, "/") + "\x00" + strconv.FormatUint(id, 10) + "\x00" + uuid))
	return hex.EncodeToString(sum[:])
}
