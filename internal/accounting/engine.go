// Package accounting calculates conservative exact counter intervals. Durable state
// and serialization belong to storage/postgres; this package has no mutable cache.
package accounting

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
)

// Attribute retains the first raw value AND the original occurrence count.
// Count zero means absent, not a malformed present value. Native SQL retains NULL.
type Attribute struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}
type Raw struct {
	SourceIP                                                                               string
	NASIP, Station, Session, Status, Duration, Input, Output, InputHigh, OutputHigh, Class Attribute
	Received                                                                               time.Time
	Location, Client, Host, ReplayID, CalledStation, NASPort                               string
}
type Event struct {
	CalledStation, NASPort     string
	ID                         string    `json:"event_id"`
	Key                        [4]string `json:"session_key"`
	Status                     string    `json:"status"`
	Duration, Upload, Download uint64
	Bits                       int
	Marked                     bool
	Received                   time.Time
	Identity                   *binding.Attribution
	AttributionIssue           string
	Location, Host             string
}
type State struct {
	Initialized                bool
	Duration, Upload, Download uint64
	Bits                       int
	Marked, Stopped            bool
	LastSeen                   time.Time
	Identity                   *binding.Attribution
}
type Interval struct {
	ID                string    `json:"usage_id"`
	Key               [4]string `json:"session_key"`
	Previous, Current [3]uint64
	Upload            uint64               `json:"upload_delta_bytes"`
	Download          uint64               `json:"download_delta_bytes"`
	Seconds           uint64               `json:"interval_seconds"`
	Received          time.Time            `json:"timestamp"`
	Bits              int                  `json:"counter_bits"`
	Identity          *binding.Attribution `json:"identity"`
}

var macRE = regexp.MustCompile(`^[0-9a-f]{12}$`)
var decimalRE = regexp.MustCompile(`^[0-9]+$`)

func CanonicalKey(r Raw) ([4]string, error) {
	k := [4]string{strings.ToLower(strings.Trim(r.SourceIP, " \t\n\r\v\f")), strings.ToLower(strings.Trim(r.NASIP.Value, " \t\n\r\v\f")), strings.ToLower(strings.NewReplacer(":", "", "-", "", ".", "").Replace(strings.Trim(r.Station.Value, " \t\n\r\v\f"))), strings.Trim(r.Session.Value, " \t\n\r\v\f")}
	_, sourceErr := netip.ParseAddr(k[0])
	_, nasErr := netip.ParseAddr(k[1])
	if sourceErr != nil || nasErr != nil || strings.Contains(k[0], "%") || strings.Contains(k[1], "%") || r.NASIP.Count != 1 || r.Station.Count != 1 || r.Session.Count != 1 || k[0] == "" || k[1] == "" || k[3] == "" || len(k[3]) > 253 || len(k[0]) > 64 || len(k[1]) > 64 || !macRE.MatchString(k[2]) {
		return k, errors.New("invalid_session_identity")
	}
	return k, nil
}

// SessionKey uses a length-prefixed key, also implemented by the intake migration.
func SessionKey(k [4]string) string {
	var b strings.Builder
	for _, v := range k {
		fmt.Fprintf(&b, "%d:%s", len(v), v)
	}
	return b.String()
}
func word(a Attribute, optional bool) (uint64, error) {
	if a.Count == 0 && optional && a.Value == "" {
		return 0, nil
	}
	if a.Count != 1 || !decimalRE.MatchString(a.Value) {
		return 0, errors.New("invalid_counter")
	}
	n, e := strconv.ParseUint(a.Value, 10, 32)
	if e != nil {
		return 0, errors.New("invalid_counter")
	}
	return n, nil
}
func Normalize(r Raw, key []byte, maxAge time.Duration) (Event, error) {
	k, err := CanonicalKey(r)
	if err != nil {
		return Event{}, err
	}
	e := Event{Key: k, Received: r.Received, Bits: 64, Marked: true, Location: r.Location, Host: r.Host, CalledStation: r.CalledStation, NASPort: r.NASPort}
	if r.Received.IsZero() || r.Client == "" || r.Location == "" {
		return e, errors.New("invalid_trusted_context")
	}
	if r.Status.Count != 1 {
		return e, errors.New("invalid_status")
	}
	switch r.Status.Value {
	case "Start", "1":
		e.Status = "Start"
	case "Interim-Update", "3":
		e.Status = "Interim-Update"
	case "Stop", "2":
		e.Status = "Stop"
	default:
		return e, errors.New("invalid_status")
	}
	if e.Status != "Start" {
		d, err := word(r.Duration, false)
		if err != nil {
			return e, err
		}
		e.Duration = d
		lo, err := word(r.Input, false)
		if err != nil {
			return e, err
		}
		hi, err := word(r.InputHigh, true)
		if err != nil {
			return e, err
		}
		e.Upload = lo | hi<<32
		lo, err = word(r.Output, false)
		if err != nil {
			return e, err
		}
		hi, err = word(r.OutputHigh, true)
		if err != nil {
			return e, err
		}
		e.Download = lo | hi<<32
	}
	if r.Class.Count == 1 {
		e.Identity = binding.Verify(key, []string{r.Class.Value}, r.Location, []string{r.Station.Value}, r.Received, maxAge)
	}
	if e.Identity == nil && r.Class.Count != 0 {
		e.AttributionIssue = "invalid_class"
	}
	e.ID = digest([]any{k, e.Status, e.Duration, e.Upload, e.Download, e.Bits, r.Location, r.Class})
	return e, nil
}
func digest(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// usageID preserves radius_usage.py's compact json.dumps default ensure_ascii
// serialization. Go's default HTML escaping and literal Unicode differ from that
// persisted contract. Only usage coordinates use this encoding; observation IDs
// retain their existing format.
func usageID(key [4]string, previous, current [3]uint64) string {
	var encoded strings.Builder
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	// These fixed arrays contain only strings and uint64 values, so Encode cannot fail.
	_ = encoder.Encode([]any{key, previous, current})
	var canonical strings.Builder
	for _, r := range strings.TrimSuffix(encoded.String(), "\n") {
		switch {
		case r < 0x7f:
			canonical.WriteByte(byte(r))
		case r <= 0xffff:
			_, _ = fmt.Fprintf(&canonical, `\u%04x`, r)
		default:
			high, low := utf16.EncodeRune(r)
			_, _ = fmt.Fprintf(&canonical, `\u%04x\u%04x`, high, low)
		}
	}
	sum := sha256.Sum256([]byte(canonical.String()))
	return hex.EncodeToString(sum[:])
}

// Apply mirrors the legacy checkpoint's uncertainty rules. Missing attribution
// may inherit earlier verified evidence only within this exact session key.
func Apply(s State, e Event) (State, *Interval, string) {
	if !s.Initialized {
		return State{true, e.Duration, e.Upload, e.Download, e.Bits, e.Marked, e.Status == "Stop", e.Received, e.Identity}, nil, "baseline"
	}
	if e.Received.After(s.LastSeen) {
		s.LastSeen = e.Received
	}
	if s.Stopped || e.Status == "Start" || e.Duration < s.Duration {
		return s, nil, "ignored"
	}
	if s.Bits == 64 && s.Marked && !e.Marked && e.Bits == 32 {
		return s, nil, "legacy_uncertain"
	}
	if e.Identity != nil {
		s.Identity = e.Identity
	}
	if e.Status == "Stop" {
		s.Stopped = true
	}
	if e.Marked && e.Bits != s.Bits {
		s.Duration = e.Duration
		s.Upload = e.Upload
		s.Download = e.Download
		s.Bits = e.Bits
		s.Marked = true
		return s, nil, "precision_change"
	}
	s.Bits = max(s.Bits, e.Bits)
	s.Marked = s.Marked || e.Marked
	prev := [3]uint64{s.Duration, s.Upload, s.Download}
	cur := [3]uint64{e.Duration, e.Upload, e.Download}
	if prev == cur || (e.Duration == s.Duration && (e.Upload < s.Upload || e.Download < s.Download)) {
		return s, nil, "duplicate_or_reordered"
	}
	s.Duration = e.Duration
	s.Upload = e.Upload
	s.Download = e.Download
	if e.Upload < prev[1] || e.Download < prev[2] {
		return s, nil, "counter_reset"
	}
	return s, &Interval{ID: usageID(e.Key, prev, cur), Key: e.Key, Previous: prev, Current: cur, Upload: e.Upload - prev[1], Download: e.Download - prev[2], Seconds: e.Duration - prev[0], Received: e.Received, Bits: s.Bits, Identity: s.Identity}, "interval"
}
