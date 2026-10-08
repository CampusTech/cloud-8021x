// Package migration validates deployed state completely before a database or
// local publication callback is allowed to run. State version is not app version.
package migration

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting"
	"github.com/CampusTech/cloud-8021x/internal/domain"
)

type LegacyIdentity struct {
	Verified    bool   `json:"identity_verified"`
	DeviceID    string `json:"device_id"`
	Name        string `json:"device_name"`
	Owner       string `json:"device_owner"`
	Model       string `json:"device_model"`
	Serial      string `json:"serial"`
	Fingerprint string `json:"certificate_fingerprint"`
}
type LegacySession struct {
	Key          [4]string                  `json:"key"`
	Duration     uint64                     `json:"duration"`
	Upload       uint64                     `json:"upload"`
	Download     uint64                     `json:"download"`
	Stopped      bool                       `json:"stopped"`
	Display      map[string]json.RawMessage `json:"display"`
	Identity     *LegacyIdentity            `json:"identity"`
	LastSeen     json.Number                `json:"last_seen"`
	CounterBits  int                        `json:"counter_bits"`
	FormatMarked bool                       `json:"format_marked"`
}
type LegacyTracker struct {
	Version  int             `json:"version"`
	Sessions []LegacySession `json:"sessions"`
}
type UsageCheckpoint struct {
	Version     int               `json:"version"`
	Tracker     LegacyTracker     `json:"tracker"`
	Through     json.RawMessage   `json:"through"`
	Pending     []json.RawMessage `json:"pending"`
	Uncertain   bool              `json:"uncertain"`
	Seeded      bool              `json:"seeded"`
	PreviewID   *string           `json:"preview_id"`
	CreditStart json.RawMessage   `json:"credit_start,omitempty"`
}

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func requireFields(data []byte, required ...string) error {
	var fields map[string]json.RawMessage
	if err := domain.DecodeJSONStrict(data, &fields); err != nil || fields == nil {
		return errors.New("invalid legacy object")
	}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return errors.New("missing required legacy field")
		}
	}
	return nil
}
func DecodeUsage(data []byte, hosts []string) (UsageCheckpoint, error) {
	var c UsageCheckpoint
	bad := func() (UsageCheckpoint, error) {
		return UsageCheckpoint{}, errors.New("invalid legacy usage checkpoint")
	}
	if len(data) > 64<<20 || len(hosts) == 0 || requireFields(data, "version", "tracker", "through", "pending", "uncertain", "seeded", "preview_id") != nil || domain.DecodeJSONStrict(data, &c) != nil || c.Version != 1 || c.Tracker.Version != 1 || c.Tracker.Sessions == nil || c.Pending == nil || len(c.Tracker.Sessions) > 100000 || len(c.Pending) > 10000 {
		return bad()
	}
	var top map[string]json.RawMessage
	_ = json.Unmarshal(data, &top)
	for _, name := range []string{"uncertain", "seeded"} {
		if bytes.Equal(top[name], []byte("null")) {
			return bad()
		}
	}
	// Raw session presence/array length needs validation: a fixed Go array alone
	// would accept a short JSON array and bool zero values would hide absence.
	var raw struct {
		Tracker struct {
			Sessions []json.RawMessage `json:"sessions"`
		} `json:"tracker"`
	}
	if json.Unmarshal(data, &raw) != nil {
		return bad()
	}
	seen := map[[4]string]bool{}
	for i := range c.Tracker.Sessions {
		s := &c.Tracker.Sessions[i]
		if requireFields(raw.Tracker.Sessions[i], "key", "duration", "upload", "download", "stopped", "display", "identity", "last_seen") != nil {
			return bad()
		}
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(raw.Tracker.Sessions[i], &fields)
		var parts []string
		if json.Unmarshal(fields["key"], &parts) != nil || len(parts) != 4 {
			return bad()
		}
		for _, name := range []string{"stopped", "duration", "upload", "download", "last_seen"} {
			if bytes.Equal(fields[name], []byte("null")) {
				return bad()
			}
		}
		key, e := accounting.CanonicalKey(accounting.Raw{SourceIP: s.Key[0], NASIP: accounting.Attribute{Value: s.Key[1], Count: 1}, Station: accounting.Attribute{Value: s.Key[2], Count: 1}, Session: accounting.Attribute{Value: s.Key[3], Count: 1}})
		if e != nil || key != s.Key || seen[key] || s.Display == nil {
			return bad()
		}
		seen[key] = true
		if bytes.HasPrefix(bytes.TrimSpace(fields["last_seen"]), []byte("\"")) {
			return bad()
		}
		if _, e = ReceiptTime([]byte(s.LastSeen)); e != nil {
			return bad()
		}
		if _, ok := fields["counter_bits"]; !ok {
			s.CounterBits = 32
			if max(s.Upload, s.Download) >= 1<<32 {
				s.CounterBits = 64
			}
		}
		if (s.CounterBits != 32 && s.CounterBits != 64) || (s.CounterBits == 32 && max(s.Upload, s.Download) >= 1<<32) {
			return bad()
		}
		if bits, ok := fields["format_marked"]; ok && bytes.Equal(bits, []byte("null")) {
			return bad()
		}
		for name := range s.Display {
			if !slices.Contains([]string{"site_name", "ssid", "ap_name", "host", "vlan_id", "vlan_name", "nas_port", "called_station"}, name) {
				return bad()
			}
		}
		if s.Identity != nil && (!s.Identity.Verified || s.Identity.DeviceID == "") {
			return bad()
		}
	}
	throughAbsent := bytes.Equal(bytes.TrimSpace(c.Through), []byte("null"))
	var through time.Time
	if !throughAbsent {
		var e error
		through, e = ReceiptTime(c.Through)
		if e != nil {
			return bad()
		}
	}
	if len(c.CreditStart) != 0 {
		absent := bytes.Equal(bytes.TrimSpace(c.CreditStart), []byte("null"))
		if absent != throughAbsent {
			return bad()
		}
		if !absent {
			floor, e := ReceiptTime(c.CreditStart)
			if e != nil || floor.After(through) {
				return bad()
			}
		}
	}
	if len(c.Pending) > 0 && throughAbsent || c.Uncertain && len(c.Pending) == 0 {
		return bad()
	}
	for _, record := range c.Pending {
		var p map[string]json.RawMessage
		if domain.DecodeJSONStrict(record, &p) != nil {
			return bad()
		}
		str := func(name string) string { var s string; _ = json.Unmarshal(p[name], &s); return s }
		if str("service") != "radius-usage" || str("event") != "Acct-Usage" || !digestPattern.MatchString(str("usage_id")) || !slices.Contains(hosts, str("hostname")) {
			return bad()
		}
		if _, e := ReceiptTime(p["timestamp"]); e != nil {
			return bad()
		}
		up, e := exactCounter(p["input_bytes"])
		upload, f := exactCounter(p["upload_delta_bytes"])
		down, g := exactCounter(p["output_bytes"])
		download, h := exactCounter(p["download_delta_bytes"])
		if errors.Join(e, f, g, h) != nil || up != upload || down != download || !slices.Contains([]string{"full_64bit", "legacy_32bit", "legacy32_unknown"}, str("counter_quality")) {
			return bad()
		}
		var preview *string
		if len(p["preview_id"]) != 0 && json.Unmarshal(p["preview_id"], &preview) != nil {
			return bad()
		}
		if (preview == nil) != (c.PreviewID == nil) || preview != nil && *preview != *c.PreviewID {
			return bad()
		}
	}
	return c, nil
}
func (c UsageCheckpoint) Encode() ([]byte, error) { return json.Marshal(c) }

// ReceiptTime accepts the original numeric/ISO representation; callers retain
// that raw representation for export even when PostgreSQL rounds to microseconds.
func ReceiptTime(raw []byte) (time.Time, error) {
	text := strings.TrimSpace(string(raw))
	if strings.HasPrefix(text, "\"") {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return time.Time{}, errors.New("invalid receipt")
		}
		if t, e := time.Parse(time.RFC3339Nano, s); e == nil {
			return t, nil
		}
		text = s
	}
	value, e := strconv.ParseFloat(text, 64)
	if e != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < -62135596800 || value > 253402300799 {
		return time.Time{}, errors.New("invalid receipt")
	}
	whole, fraction := math.Modf(value)
	return time.Unix(int64(whole), int64(fraction*1e9)).UTC(), nil
}
func exactCounter(raw []byte) (uint64, error) {
	text := string(raw)
	if strings.HasPrefix(text, "\"") {
		if json.Unmarshal(raw, &text) != nil {
			return 0, errors.New("invalid counter")
		}
	}
	r, ok := new(big.Rat).SetString(text)
	if !ok || !r.IsInt() || r.Sign() < 0 || !r.Num().IsUint64() {
		return 0, errors.New("invalid unsigned counter")
	}
	return r.Num().Uint64(), nil
}
