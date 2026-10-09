package scenariocontract

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting"
	"github.com/CampusTech/cloud-8021x/internal/domain"
)

func utc(t time.Time) bool   { _, offset := t.Zone(); return !t.IsZero() && offset == 0 }
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func DecodeResult(raw []byte, r Request, requestSHA string) (Result, error) {
	var v Result
	if len(raw) > MaxResultBytes || decodeCanonicalJSON(raw, &v) != nil {
		return v, errors.New("bounded strict scenario result required")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return v, errors.New("result object required")
	}
	for _, k := range []string{"probe", "ledger", "lifecycle", "nas", "ca", "ca_issued", "gate", "cleanup"} {
		if _, ok := fields[k]; ok && k != bodyKind(r.Action) {
			return v, errors.New("irrelevant result body presence refused")
		}
	}
	return v, v.Validate(r, requestSHA)
}
func (v Result) Validate(r Request, requestSHA string) error {
	if e := r.Validate(); e != nil {
		return e
	}
	if v.Schema != 1 || v.Kind != "scenario-operation" || v.AttemptID != r.AttemptID || v.Sequence != r.Sequence || v.Action != r.Action || v.Pins != r.Pins || !hashPattern.MatchString(requestSHA) || v.RequestSHA256 != requestSHA || !v.Retired || !utc(v.StartedAt) || !utc(v.FinishedAt) || v.FinishedAt.Before(v.StartedAt) || v.FinishedAt.Sub(v.StartedAt) > 20*time.Minute {
		return errors.New("independent result pins, bounded timestamps and actual retirement required")
	}
	present := map[string]bool{"probe": v.Probe != nil, "ledger": v.Ledger != nil, "lifecycle": v.Lifecycle != nil, "nas": v.NAS != nil, "ca": v.CA != nil, "ca_issued": v.CAIssued != nil, "gate": v.Gate != nil, "cleanup": v.Cleanup != nil}
	for k, ok := range present {
		if ok != (k == bodyKind(r.Action)) {
			return errors.New("exactly one matching result body required")
		}
	}
	switch bodyKind(r.Action) {
	case "probe":
		if len(v.Probe.Nodes) != 2 {
			return errors.New("both measured green nodes required")
		}
		for _, n := range []string{"green-primary", "green-secondary"} {
			p, ok := v.Probe.Nodes[n]
			if !ok {
				return errors.New("unknown active-pair node")
			}
			if e := validateNode(n, p, r.ApplicationSHA256); e != nil {
				return e
			}
		}
		primary, secondary := v.Probe.Nodes["green-primary"], v.Probe.Nodes["green-secondary"]
		if primary.MachineID == secondary.MachineID || primary.Leader == secondary.Leader || (primary.Collector.FileDevice == secondary.Collector.FileDevice && primary.Collector.FileInode == secondary.Collector.FileInode) {
			return errors.New("active pair shares a physical node or durable collector")
		}
		for _, name := range []string{"pid", "mnt", "uts", "net", "cgroup"} {
			if primary.Namespaces[name] == secondary.Namespaces[name] {
				return errors.New("active pair shares a measured namespace")
			}
		}
	case "ledger":
		return validateLedger(*v.Ledger, r)
	case "nas":
		return validateNAS(*v.NAS)
	case "ca":
		return validateCAResult(*v.CA, r.Action)
	case "ca_issued":
		return validateCAObservation(*v.CAIssued, r)
	case "lifecycle":
		l := v.Lifecycle
		if l.Unit != "task11-node-green-primary.service" || !l.OldLeaderRetired {
			return errors.New("bound primary retirement required")
		}
		if r.Action == "stop-green-primary" {
			if l.Before == nil || l.After != nil || l.UnitActiveState != "inactive" || l.UnitSubState != "dead" {
				return errors.New("actual stopped primary observation required")
			}
			return validateNode("green-primary", *l.Before, r.ApplicationSHA256)
		}
		if l.After == nil || l.UnitActiveState != "active" || l.UnitSubState != "running" {
			return errors.New("actual new primary observation required")
		}
		if e := validateNode("green-primary", *l.After, r.ApplicationSHA256); e != nil {
			return e
		}
		if l.Before != nil {
			if e := validateNode("green-primary", *l.Before, r.ApplicationSHA256); e != nil {
				return e
			}
			if l.Before.BootID == l.After.BootID || (l.Before.Leader == l.After.Leader && l.Before.LeaderStartTicks == l.After.LeaderStartTicks) {
				return errors.New("changed boot and retired leader required")
			}
		} else if r.Action == "reboot-green-primary" {
			return errors.New("reboot before-state required")
		}
	case "gate":
		g := v.Gate
		if !utc(g.ObservedAt) {
			return errors.New("fresh gate observation required")
		}
		if strings.HasSuffix(r.Action, "postgres") {
			if g.Unit != "task11-postgres.service" {
				return errors.New("only the enrolled PostgreSQL unit may be controlled")
			}
			if (r.Action == "stop-postgres" && (g.State != "inactive" || g.MainPID != 0 || !g.OldPIDRetired)) || (r.Action == "start-postgres" && (g.State != "active" || g.MainPID < 2)) {
				return errors.New("actual database unit lifecycle required")
			}
		} else if g.Unit != "" || g.MainPID != 0 || g.State != r.Action {
			return errors.New("fixed intake gate observation required")
		}
	case "cleanup":
		if len(v.Cleanup.Cases) != 2 {
			return errors.New("both owned cleanup cases required")
		}
		seen := map[string]bool{}
		for _, c := range v.Cleanup.Cases {
			if (c.Kind != "deadline" && c.Kind != "helper-death") || seen[c.Kind] || c.Populated || !c.SentinelObservedAlive || !c.SentinelRetired || len(c.Processes) < 2 || len(c.Processes) > 8 {
				return errors.New("actual operation quiescence and unaffected sentinel required")
			}
			seen[c.Kind] = true
			for _, p := range c.Processes {
				if p.HostPID < 2 || p.StartTicks == 0 || !p.Retired || !strings.HasPrefix(p.ControlGroup, "/system.slice/task11-acceptance.service/operation-") {
					return errors.New("bound owned process retirement required")
				}
			}
		}
	}
	return nil
}

var machinePattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var bootPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var stationPattern = regexp.MustCompile(`^[0-9a-f]{12}$`)

func validateNode(n string, p NodeObservation, app string) error {
	if (n != "green-primary" && n != "green-secondary") || p.Machine != "task11-"+n || p.Root != "/var/lib/cloud8021x-task11/roots/"+p.Machine || !machinePattern.MatchString(p.MachineID) || !bootPattern.MatchString(p.BootID) || p.Leader < 2 || p.LeaderStartTicks == 0 || p.ApplicationSHA256 != app || !hashPattern.MatchString(p.ConfigSHA256) || p.Deployment != "task11-green" || !utc(p.Epoch) || !p.WorkersActive || p.WorkersBlocked || p.ReadyRoles != 2 || len(p.Namespaces) != 5 {
		return errors.New("genuine active node identity required")
	}
	for _, k := range []string{"pid", "mnt", "uts", "net", "cgroup"} {
		if p.Namespaces[k] == 0 {
			return errors.New("all five measured namespaces required")
		}
	}
	units := []string{"cloud-8021x.service", "freeradius.service", "step-ca.service", "step-ca-rsa.service", "datadog-agent.service", "datadog-agent-ddot.service"}
	if len(p.Units) != len(units) {
		return errors.New("complete fixed shipping unit set required")
	}
	for _, k := range units {
		u, ok := p.Units[k]
		if !ok || u.Name != k || u.ActiveState != "active" || u.MainPID < 2 || !hashPattern.MatchString(u.ExecutableSHA256) || u.ControlGroup == "" || u.ProcessCgroup != u.ControlGroup || u.FragmentPath == "" || len(u.DropInPaths) > 8 {
			return errors.New("actual PID1 unit and process identity required")
		}
	}
	c := p.Collector
	if c.BackingFile != "/var/lib/cloud-8021x-bootstrap/collector.ext4" || c.FileDevice == 0 || c.FileInode == 0 || c.ByteSize != 512<<20 || c.Filesystem != "ext4" || !c.MountActive || c.MountDevice == "" || len(c.Options) > 32 {
		return errors.New("actual durable collector allocation required")
	}
	for _, k := range []string{"nodev", "nosuid", "noexec"} {
		if !slices.Contains(c.Options, k) {
			return errors.New("collector mount safety options required")
		}
	}
	return nil
}
func selectedKey(encoded string, selected []string) bool {
	var key [4]string
	original := encoded
	for i := range key {
		length, rest, ok := strings.Cut(encoded, ":")
		if !ok {
			return false
		}
		n, e := strconv.Atoi(length)
		if e != nil || n < 1 || n > 253 || strconv.Itoa(n) != length || len(rest) < n {
			return false
		}
		key[i], encoded = rest[:n], rest[n:]
	}
	return encoded == "" && key[0] == "10.203.11.40" && key[1] == "10.203.11.40" && stationPattern.MatchString(key[2]) && slices.Contains(selected, key[3]) && accounting.SessionKey(key) == original
}
func validateLedger(l LedgerObservation, r Request) error {
	if l.Deployment != "task11-green" || l.Database != "cloud8021x_task11_green" || !utc(l.Epoch) || !hashPattern.MatchString(l.ConfigSHA256) || !l.ReadOnly || l.Isolation != "repeatable-read" || len(l.Sessions) > 8 || len(l.Observations) > 128 || len(l.Intervals) > 128 || len(l.Outbox) > 256 {
		return errors.New("bounded read-only selected ledger observation required")
	}
	keys := map[string]bool{}
	for _, s := range l.Sessions {
		if !selectedKey(s.SessionKey, r.Sessions) || keys[s.SessionKey] || (s.State.Bits != 32 && s.State.Bits != 64) {
			return errors.New("foreign or duplicate ledger session")
		}
		keys[s.SessionKey] = true
	}
	events := map[string]string{}
	for _, e := range l.Observations {
		if !selectedKey(e.SessionKey, r.Sessions) || !keys[e.SessionKey] || !hashPattern.MatchString(e.EventID) || e.Event.ID != e.EventID || events[e.EventID] != "" || e.IntakeID < 1 || accounting.SessionKey(e.Event.Key) != e.SessionKey || !utc(e.ReceivedAt) || !e.Event.Received.Equal(e.ReceivedAt) {
			return errors.New("foreign or ambiguous accounting observation")
		}
		events[e.EventID] = e.SessionKey
	}
	usages := map[string]bool{}
	for _, i := range l.Intervals {
		if !selectedKey(i.SessionKey, r.Sessions) || !keys[i.SessionKey] || !hashPattern.MatchString(i.UsageID) || i.Interval.ID != i.UsageID || usages[i.UsageID] || events[i.EventID] != i.SessionKey || accounting.SessionKey(i.Interval.Key) != i.SessionKey {
			return errors.New("foreign or ambiguous usage interval")
		}
		usages[i.UsageID] = true
	}
	budget := MaxOpaqueBytes
	work := map[string]bool{}
	for _, w := range l.Outbox {
		prefix, id, ok := strings.Cut(w.ID, ":")
		selected := (prefix == "accounting" && events[id] != "") || (prefix == "usage" && usages[id])
		if !ok || w.Kind != "outbox" || work[w.ID] || !selected || !slices.Contains([]string{"pending", "leased", "started", "succeeded", "quarantine"}, w.State) || !utc(w.CreatedAt) || len(w.Attempts) > 16 {
			return errors.New("foreign or ambiguous selected outbox work")
		}
		work[w.ID] = true
		for _, b := range [][]byte{w.Payload, w.Receipt, w.RecoveryEvidence} {
			budget -= len(b)
			if budget < 0 {
				return errors.New("opaque byte budget exceeded")
			}
		}
		if !strictObject(w.Payload) {
			return errors.New("stored work payload is not a strict object")
		}
		previous := int64(0)
		for _, a := range w.Attempts {
			if a.Generation <= previous || !utc(a.StartedAt) {
				return errors.New("ordered actual delivery attempts required")
			}
			previous = a.Generation
			budget -= len(a.Receipt)
			if budget < 0 {
				return errors.New("opaque attempt byte budget exceeded")
			}
		}
	}
	return nil
}
func strictObject(b []byte) bool {
	var v map[string]json.RawMessage
	return domain.DecodeJSONStrict(b, &v) == nil && v != nil
}
func DecodeCASelection(raw []byte) (CASelection, error) {
	var s CASelection
	if len(raw) > MaxRequestBytes || decodeCanonicalJSON(raw, &s) != nil || s.Schema != 1 || !attemptPattern.MatchString(s.AttemptID) || s.IssuanceSequence < 1 || s.IssuanceSequence > MaxSequence || (s.Authority != "ec" && s.Authority != "rsa") || !serialPattern.MatchString(s.Serial) {
		return s, errors.New("bounded genuine issued-result selection required")
	}
	for _, p := range []string{s.ResultSHA256, s.LeafDERSHA256, s.OriginalRootSHA256, s.OriginalIntermediateSHA256} {
		if !hashPattern.MatchString(p) {
			return s, errors.New("independent issued-result and original chain pins required")
		}
	}
	return s, nil
}
func validateCAObservation(c CAObservation, r Request) error {
	expected := map[string]string{"ec": "stepca", "rsa": "stepca_rsa"}
	if expected[c.Authority] == "" || c.Database != expected[c.Authority] || !c.ReadOnly || c.Isolation != "repeatable-read" || !serialPattern.MatchString(c.Serial) || c.SelectionSHA256 != r.SelectionSHA256 || !hashPattern.MatchString(c.IssuanceResultSHA256) || !hashPattern.MatchString(c.LeafDERSHA256) || !bytes.Equal(c.CertificateKey, []byte(c.Serial)) || len(c.CertificateDER) > 1<<20 || len(c.CertificateData) > 1<<20 {
		return errors.New("fixed genuine CA row observation required")
	}
	leaf, e := x509.ParseCertificate(c.CertificateDER)
	if e != nil || leaf.SerialNumber.String() != c.Serial || digest(c.CertificateDER) != c.LeafDERSHA256 {
		return errors.New("stored certificate DER identity differs")
	}
	if c.CertificateDataPresent {
		if !bytes.Equal(c.CertificateDataKey, c.CertificateKey) || !strictObject(c.CertificateData) {
			return errors.New("actual provisioner metadata row differs")
		}
	} else if len(c.CertificateDataKey) != 0 || len(c.CertificateData) != 0 || c.Authority == "rsa" {
		return errors.New("RSA metadata required; EC absence must be explicit and unmodified")
	}
	return nil
}
func validateCAResult(c CAResult, action string) error {
	if (c.Authority != "ec" && c.Authority != "rsa") || (c.Authority == "ec" && c.Route != "ec-legacy-mtls-renew") || (c.Authority == "rsa" && c.Route != "rsa-scep") || c.Phase != strings.TrimPrefix(action, "nas-ca-") {
		return errors.New("fixed genuine CA route and phase required")
	}
	peers := []string{"10.203.11.21", "10.203.11.22"}
	if c.Phase == "original" {
		peers = []string{"10.203.11.31", "10.203.11.32"}
	}
	if !slices.Contains(peers, c.Peer) {
		return errors.New("CA peer outside the enrolled phase")
	}
	for _, p := range []string{c.RequestSHA256, c.SignerPublicSHA256, c.OriginalRootSHA256, c.OriginalIntermediateSHA256} {
		if !hashPattern.MatchString(p) {
			return errors.New("genuine CA input pins required")
		}
	}
	if (c.Authority == "rsa" && !hashPattern.MatchString(c.OriginalDecrypterSHA256)) || (c.Authority == "ec" && c.OriginalDecrypterSHA256 != "") {
		return errors.New("authority-specific decrypter pin required")
	}
	if c.Response.HTTPStatus < 0 || c.Response.HTTPStatus > 599 || len(c.Response.Code) > 64 || (c.Response.Code != "" && !regexp.MustCompile(`^[a-z0-9-]+$`).MatchString(c.Response.Code)) {
		return errors.New("bounded nonsecret CA response required")
	}
	if c.Issued == nil {
		if c.Response.HTTPStatus == 200 && c.Response.Code == "" {
			return errors.New("successful response lacks actual certificate")
		}
		return nil
	}
	i := c.Issued
	leaf, e := x509.ParseCertificate(i.LeafDER)
	if len(i.LeafDER) > 1<<20 || e != nil || !serialPattern.MatchString(i.Serial) || leaf.SerialNumber.String() != i.Serial || digest(i.LeafDER) != i.LeafDERSHA256 || !i.NotBefore.Equal(leaf.NotBefore) || !i.NotAfter.Equal(leaf.NotAfter) || i.Subject != leaf.Subject.String() || !i.ClientAuthOnly || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(leaf.UnknownExtKeyUsage) != 0 {
		return errors.New("issued leaf metadata differs from actual public DER")
	}
	public, e := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if e != nil || digest(public) != i.PublicKeySHA256 || !c.Response.SignatureVerified || !c.Response.TransactionBound || !c.Response.ChainVerified {
		return errors.New("actual issued signature, transaction and chain evidence required")
	}
	return nil
}
func validateNAS(n NASResult) error {
	if _, e := accounting.CanonicalKey(accounting.Raw{SourceIP: "10.203.11.40", NASIP: accounting.Attribute{Value: "10.203.11.40", Count: 1}, Station: accounting.Attribute{Value: n.Station, Count: 1}, Session: accounting.Attribute{Value: n.Session, Count: 1}}); e != nil {
		return errors.New("canonical observed NAS station/session required")
	}
	if !slices.Contains([]string{"10.203.11.21", "10.203.11.22"}, n.Peer) || !sessionPattern.MatchString(n.Session) || !utc(n.ChosenAt) || len(n.Packets) > 16 {
		return errors.New("bounded independently chosen NAS context required")
	}
	if !n.EAP.Accepted {
		if n.ClassSHA256 != "" || n.Attribution.DeviceID != "" || len(n.Packets) != 0 || len(n.Expected.EventIDs) != 0 || len(n.Expected.UsageIDs) != 0 {
			return errors.New("unaccepted EAP cannot supply attribution or accounting evidence")
		}
		return nil
	}
	if n.EAP.Rejected || n.EAP.ResponseCode != 2 || !hashPattern.MatchString(n.EAP.ResponseAuthenticatorSHA256) || n.EAP.TunnelType != 13 || n.EAP.TunnelMediumType != 6 || n.EAP.VLAN != 120 || !hashPattern.MatchString(n.ClassSHA256) || n.Attribution.DeviceID == "" || !hashPattern.MatchString(n.Attribution.Fingerprint) || n.Attribution.VLAN == nil || *n.Attribution.VLAN != 120 || !utc(n.Attribution.IssuedAt) || len(n.Expected.EventIDs) < 1 || len(n.Expected.EventIDs) > 16 || len(n.Expected.UsageIDs) > 16 {
		return errors.New("genuine verified signed attribution and numeric VLAN response required")
	}
	for _, ids := range [][]string{n.Expected.EventIDs, n.Expected.UsageIDs} {
		seen := map[string]bool{}
		for _, id := range ids {
			if !hashPattern.MatchString(id) || seen[id] {
				return errors.New("unique pre-accounting expected IDs required")
			}
			seen[id] = true
		}
	}
	for _, p := range n.Packets {
		if !slices.Contains([]string{"10.203.11.21", "10.203.11.22"}, p.Peer) || !slices.Contains([]int{1, 2, 3}, p.Status) || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(p.RequestAuthenticator) || !utc(p.SentAt) || !utc(p.CompletedAt) || p.CompletedAt.Before(p.SentAt) || p.SentAt.Before(n.ChosenAt) {
			return errors.New("actual bounded signed accounting packet observation required")
		}
		if p.ACK && (p.ResponseCode != 5 || !hashPattern.MatchString(p.ResponseAuthenticatorSHA256)) {
			return errors.New("ACK requires authenticated native accounting response")
		}
		if !p.ACK && p.ResponseCode == 5 {
			return errors.New("unverified response cannot claim native ACK")
		}
	}
	return nil
}
