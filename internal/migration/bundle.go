package migration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/network"
)

// Bundle is an explicit state schema independent of executable version. Documents
// retain their original JSON, including numeric precision and null ambiguity.
// Class key BYTES stay in the protected local archive, never in PostgreSQL.
type Bundle struct {
	Version             int             `json:"version"`
	Node                string          `json:"node"`
	Policy              json.RawMessage `json:"policy"`
	Certificates        json.RawMessage `json:"certificates,omitempty"`
	Readiness           json.RawMessage `json:"readiness,omitempty"`
	Devices             json.RawMessage `json:"devices,omitempty"`
	UniFi               *LegacyFile     `json:"unifi,omitempty"`
	Meraki              *LegacyFile     `json:"meraki,omitempty"`
	VLANs               json.RawMessage `json:"vlans,omitempty"`
	Discovery           json.RawMessage `json:"discovery,omitempty"`
	Usage               json.RawMessage `json:"usage"`
	UsageAbsent         bool            `json:"usage_absent"`
	SQL                 LegacySQL       `json:"sql"`
	ClassKeySHA256      string          `json:"class_key_sha256"`
	FingerprintEnforced bool            `json:"fingerprint_enforced"`
}
type LegacyFile struct {
	ModifiedAt json.Number     `json:"modified_at"`
	Data       json.RawMessage `json:"data"`
}
type LegacySQL struct {
	Status string         `json:"status"`
	Rows   []LegacySQLRow `json:"rows,omitempty"`
}

// Explicit operator projection of retained radacct. NAS address is not asserted
// to be packet source; rows with no source provenance remain reconciliation data.
type LegacySQLRow struct {
	ID             uint64  `json:"radacctid"`
	UniqueID       string  `json:"acctuniqueid"`
	SessionID      string  `json:"acctsessionid"`
	Username       string  `json:"username"`
	NASAddress     string  `json:"nasipaddress"`
	CallingStation string  `json:"callingstationid"`
	CalledStation  string  `json:"calledstationid"`
	Start          *string `json:"acctstarttime"`
	Update         *string `json:"acctupdatetime"`
	Stop           *string `json:"acctstoptime"`
	Duration       *uint64 `json:"acctsessiontime"`
	Input          *uint64 `json:"acctinputoctets"`
	Output         *uint64 `json:"acctoutputoctets"`
	TerminateCause string  `json:"acctterminatecause"`
}
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
func DecodeBundle(raw []byte) (Bundle, error) {
	var b Bundle
	bad := func() (Bundle, error) { return Bundle{}, errors.New("invalid complete legacy bundle") }
	if len(raw) > 96<<20 || domain.DecodeJSONStrict(raw, &b) != nil || b.Version != 1 || (b.Node != "radius-primary" && b.Node != "radius-secondary") || !digestPattern.MatchString(b.ClassKeySHA256) {
		return bad()
	}
	policy, e := domain.DecodeSnapshot(bytes.NewReader(b.Policy))
	if e != nil || b.FingerprintEnforced && policy.Version != 2 {
		return bad()
	}
	if b.UsageAbsent {
		if len(b.Usage) != 0 && string(b.Usage) != "null" {
			return bad()
		}
	} else if _, e = DecodeUsage(b.Usage, []string{"radius-primary", "radius-secondary"}); e != nil {
		return bad()
	}
	if len(b.Certificates) > 0 {
		if _, e = DecodeCertificates(b.Certificates); e != nil {
			return bad()
		}
	}
	if e = validateSQL(b.SQL); e != nil {
		return bad()
	}
	if len(b.Devices) > 0 {
		var devices map[string]struct {
			Email string      `json:"email"`
			Name  string      `json:"device_name"`
			Model string      `json:"device_model"`
			Time  json.Number `json:"ts"`
		}
		if domain.DecodeJSONStrict(b.Devices, &devices) != nil || devices == nil || len(devices) > 200000 {
			return bad()
		}
		for key, d := range devices {
			if key == "" || len(key) > 1024 || len(d.Email) > 1024 || len(d.Name) > 1024 || len(d.Model) > 1024 || originalTime(d.Time) != nil {
				return bad()
			}
		}
	}
	for i, f := range []*LegacyFile{b.UniFi, b.Meraki} {
		if f != nil {
			if originalTime(f.ModifiedAt) != nil || validateAP(f.Data, i == 0) != nil {
				return bad()
			}
		}
	}
	if len(b.Discovery) > 0 {
		var d struct {
			Updated json.Number         `json:"updated_at"`
			Sources map[string][]string `json:"sources"`
			Hosts   map[string]string   `json:"host_ids"`
		}
		if domain.DecodeJSONStrict(b.Discovery, &d) != nil || originalTime(d.Updated) != nil || d.Sources == nil || d.Hosts == nil || len(d.Sources) > 128 {
			return bad()
		}
		for office, cidrs := range d.Sources {
			if office == "" || len(cidrs) > 64 {
				return bad()
			}
			for _, cidr := range cidrs {
				p, e := netip.ParsePrefix(cidr)
				if e != nil || p != p.Masked() {
					return bad()
				}
			}
		}
	}
	if len(b.VLANs) > 0 {
		var v struct {
			Locations map[string]struct {
				Source  json.RawMessage   `json:"source"`
				Updated json.Number       `json:"updated_at"`
				Names   map[string]string `json:"names"`
			} `json:"locations"`
		}
		if domain.DecodeJSONStrict(b.VLANs, &v) != nil || v.Locations == nil || len(v.Locations) > 128 {
			return bad()
		}
		for _, scope := range v.Locations {
			if originalTime(scope.Updated) != nil || scope.Names == nil || len(scope.Source) > 4096 {
				return bad()
			}
			for id, name := range scope.Names {
				n, e := strconv.Atoi(id)
				if e != nil || !domain.ValidVLAN(n) || !network.Name(name) {
					return bad()
				}
			}
		}
	}
	// Readiness is explanatory, never certificate authority. Preserve its exact
	// legacy report while bounding and validating required original observation.
	if len(b.Readiness) > 0 {
		var r map[string]json.RawMessage
		if domain.DecodeJSONStrict(b.Readiness, &r) != nil || len(r) > 32 {
			return bad()
		}
		if _, e := ReceiptTime(r["updated_at"]); e != nil {
			return bad()
		}
	}
	return b, nil
}
func validateAP(raw []byte, unifi bool) error {
	type entry struct {
		AP   string `json:"ap_name"`
		Site string `json:"site_name"`
	}
	var v struct {
		Devices map[string]string `json:"devices,omitempty"`
		Sites   map[string]string `json:"sites,omitempty"`
		ByMAC   map[string]*entry `json:"by_mac"`
		ByBSSID map[string]*entry `json:"by_bssid,omitempty"`
	}
	if len(raw) > 16<<20 || domain.DecodeJSONStrict(raw, &v) != nil || v.ByMAC == nil || len(v.ByMAC)+len(v.ByBSSID)+len(v.Devices)+len(v.Sites) > 100000 || unifi && (v.Devices == nil || v.Sites == nil) || !unifi && (v.Devices != nil || v.Sites != nil || v.ByBSSID == nil) {
		return errors.New("invalid legacy AP cache")
	}
	for _, m := range []map[string]*entry{v.ByMAC, v.ByBSSID} {
		for mac, e := range m {
			if network.MAC(mac) == "" || e != nil && (!network.Name(e.AP) || !network.Name(e.Site)) {
				return errors.New("invalid AP ambiguity or label")
			}
		}
	}
	return nil
}
func validateSQL(s LegacySQL) error {
	if s.Status != "absent" && s.Status != "exported" || s.Status == "absent" && s.Rows != nil || s.Status == "exported" && s.Rows == nil || len(s.Rows) > 100000 {
		return errors.New("old SQL state unavailable or incomplete")
	}
	seen := map[uint64]bool{}
	for _, r := range s.Rows {
		if r.ID == 0 || seen[r.ID] || r.UniqueID == "" || r.SessionID == "" || len(r.Username) > 253 || len(r.SessionID) > 253 {
			return errors.New("invalid retained radacct row")
		}
		seen[r.ID] = true
		if _, e := netip.ParseAddr(r.NASAddress); e != nil {
			return e
		}
		for _, at := range []*string{r.Start, r.Update, r.Stop} {
			if at != nil {
				raw, _ := json.Marshal(*at)
				if _, e := ReceiptTime(raw); e != nil {
					return e
				}
			}
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
