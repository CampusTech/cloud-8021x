package contract

import (
	"errors"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var hex40 = regexp.MustCompile(`^[0-9a-f]{40}$`)
var machine = regexp.MustCompile(`^[0-9a-f]{32}$`)
var boot = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func DigestValid(s string) bool { return hex64.MatchString(s) }
func ValidateRequest(r Request) error {
	if r.Schema != 1 || !slices.Contains([]string{"green-primary", "green-secondary"}, r.Node) || !slices.Contains([]string{"prepared", "deactivated"}, r.Phase) || !machine.MatchString(r.MachineID) || !boot.MatchString(r.BootID) || !hex40.MatchString(r.ApplicationSourceSHA) {
		return errors.New("unknown enrolled request identity")
	}
	for _, s := range []string{r.Pin, r.ApplicationSHA256, r.ConfigSHA256, r.ControllerSHA256, r.ObserverSHA256, r.SeedSHA256, r.OriginalSeedSHA256} {
		if !hex64.MatchString(s) {
			return errors.New("incomplete protected pin")
		}
	}
	if len(r.Namespaces) != len(NamespaceNames) {
		return errors.New("namespace set incomplete")
	}
	for _, n := range NamespaceNames {
		if !regexp.MustCompile(`^` + n + `:\[[1-9][0-9]*\]$`).MatchString(r.Namespaces[n]) {
			return errors.New("namespace identity invalid")
		}
	}
	return nil
}
func ValidateManifest(m Manifest, r Request) error {
	if m.Schema != 1 || m.OriginalSeedSHA256 != r.OriginalSeedSHA256 || !hex64.MatchString(m.CertificateStateSHA256) || len(m.Slots) != len(Slots) {
		return errors.New("independent seed manifest differs")
	}
	for _, n := range Slots {
		if !hex64.MatchString(m.Slots[n]) {
			return errors.New("closed preserved slot missing")
		}
	}
	return nil
}
func WorkerMasked(n string) bool {
	return slices.Contains([]string{"cloud-8021x.service", "cloud-8021x-renew.service", "cloud-8021x-sources.service", "cloud-8021x-renew.timer", "cloud-8021x-sources.timer"}, n)
}
func ValidateUnits(units []Unit, phase string) error {
	if phase != "prepared" && phase != "deactivated" {
		return errors.New("unknown passive phase")
	}
	if len(units) != len(Services)+len(Timers) {
		return errors.New("closed unit set incomplete")
	}
	seen := map[string]bool{}
	for _, u := range units {
		if seen[u.Name] || (!slices.Contains(Services, u.Name) && !slices.Contains(Timers, u.Name)) {
			return errors.New("duplicate/unknown unit")
		}
		seen[u.Name] = true
		if u.MainPID != 0 || u.ControlPID != 0 {
			return errors.New("unit owns a live process")
		}
		if phase == "deactivated" && WorkerMasked(u.Name) {
			if u.LoadState != "masked" || u.UnitFileState != "masked" || u.FragmentPath != "/dev/null" || u.ActiveState != "inactive" || u.SubState != "dead" {
				return errors.New("deactivated worker mask not observed")
			}
			continue
		}
		if u.LoadState != "loaded" || !slices.Contains([]string{"enabled", "disabled", "static"}, u.UnitFileState) {
			return errors.New("unit unavailable or unknown enable state")
		}
		if slices.Contains(Services, u.Name) {
			expectedDropins := "/etc/systemd/system/" + u.Name + ".d/parallel.conf"
			if u.Name == "freeradius.service" {
				expectedDropins = "/etc/systemd/system/freeradius.service.d/cloud8021x.conf " + expectedDropins
			}
			if u.ActiveState != "inactive" || u.SubState != "dead" || !slices.Contains([]string{"yes", "no"}, u.ConditionResult) || u.DropInPaths != expectedDropins || u.ControlGroup != "" {
				return errors.New("guarded mutating service not passive")
			}
		} else {
			if u.FragmentPath != "/etc/systemd/system/"+u.Name || u.DropInPaths != "" {
				return errors.New("timer effective configuration differs")
			}
			if u.Triggers != strings.TrimSuffix(u.Name, ".timer")+".service" {
				return errors.New("timer target differs")
			}
			stopped := u.ActiveState == "inactive" && u.SubState == "dead"
			waiting := phase == "prepared" && u.ActiveState == "active" && u.SubState == "waiting" && u.UnitFileState == "enabled"
			if !stopped && !waiting {
				return errors.New("timer not safely waiting or stopped")
			}
		}
	}
	return nil
}
func ValidateSQL(s SQL, phase string) error {
	if s.Database != "cloud8021x_task11_green" || s.Deployment != "task11-green" || !hex64.MatchString(s.Transition) || !hex64.MatchString(s.ManifestSHA256) || s.Epoch.IsZero() || s.Enabled || s.WorkersAllowed || s.Blocked != (phase == "deactivated") || s.Ready < 0 || s.Ready > 2 || (phase == "prepared" && s.Ready != 0) {
		return errors.New("actual SQL passive transition differs")
	}
	if phase != "prepared" && phase != "deactivated" {
		return errors.New("unknown SQL phase")
	}
	if s.WorkRows < 0 || s.WorkRows > 4096 || s.AttemptRows < 0 || s.AttemptRows > 4096 || s.GuardRows < 0 || s.GuardRows > 128 {
		return errors.New("SQL snapshot bound exceeded")
	}
	for _, h := range []string{s.WorkSHA256, s.AttemptsSHA256, s.GuardsSHA256, s.AuthorizationSHA256} {
		if !hex64.MatchString(h) {
			return errors.New("SQL snapshot digest absent")
		}
	}

	if len(s.Prepared) != 2 {
		return errors.New("both physical prepared receipts required")
	}
	seenPrepared := map[string]bool{}
	ready := 0
	for _, n := range s.Prepared {
		if !slices.Contains([]string{"radius-primary", "radius-secondary"}, n.Role) || seenPrepared[n.Role] || n.Instance != "task11-green"+strings.TrimPrefix(n.Role, "radius") || !machine.MatchString(n.Receipt) {
			return errors.New("prepared role/receipt invalid")
		}
		seenPrepared[n.Role] = true
		for _, h := range []string{n.ConfigSHA256, n.ReleaseSHA256, n.SourceSHA256, n.TrustSHA256, n.CertificateStateSHA256, n.PolicySHA256} {
			if !hex64.MatchString(h) {
				return errors.New("prepared identity digest missing")
			}
		}
		if n.Ready {
			ready++
		}
	}
	if ready != s.Ready {
		return errors.New("prepared readiness count differs")
	}
	for i, fs := range [][]Fence{s.WriterFences, s.WorkerFences} {
		if i == 1 && phase == "prepared" {
			if len(fs) != 0 {
				return errors.New("unexpected prepared worker fences")
			}
			continue
		}
		if len(fs) != 2 {
			return errors.New("both original fences required")
		}
		seen := map[string]bool{}
		for _, f := range fs {
			if !slices.Contains([]string{"radius-primary", "radius-secondary"}, f.Node) || seen[f.Node] || !hex64.MatchString(f.ReceiptSHA256) || (i == 0 && !hex64.MatchString(f.ConfigSHA256)) {
				return errors.New("fence identity invalid")
			}
			seen[f.Node] = true
		}
	}
	return nil
}
func ValidateSockets(sockets []Socket, ports []uint16) error {
	if len(sockets) > 4096 {
		return errors.New("socket bound exceeded")
	}
	for _, s := range sockets {
		if !slices.Contains([]string{"tcp", "tcp6", "udp", "udp6"}, s.Protocol) {
			return errors.New("unknown socket protocol")
		}
		_, p, e := net.SplitHostPort(s.Local)
		if e != nil {
			return errors.New("local socket malformed")
		}
		pn, e := strconv.ParseUint(p, 10, 16)
		if e != nil {
			return errors.New("socket port malformed")
		}
		if slices.Contains(ports, uint16(pn)) && (strings.HasPrefix(s.Protocol, "udp") || s.State == "0A") {
			return errors.New("admission listener present")
		}
		h, rp, e := net.SplitHostPort(s.Remote)
		if e != nil {
			return errors.New("remote socket malformed")
		}
		if (h == "10.203.11.10" || h == "169.254.169.254") && (rp == "443" || rp == "80") && (strings.HasPrefix(s.Protocol, "udp") || s.State != "06") {
			return errors.New("mutating peer connection present")
		}
	}
	return nil
}
