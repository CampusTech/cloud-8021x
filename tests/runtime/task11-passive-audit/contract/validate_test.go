package contract

import (
	"strings"
	"testing"
	"time"
)

func request() Request {
	r := Request{Schema: 1, Node: "green-primary", Phase: "prepared", MachineID: strings.Repeat("a", 32), Pin: strings.Repeat("b", 64), BootID: "11111111-2222-4333-8444-555555555555", ApplicationSourceSHA: strings.Repeat("a", 40), Namespaces: map[string]string{}}
	for _, s := range NamespaceNames {
		r.Namespaces[s] = s + ":[123]"
	}
	r.ApplicationSHA256 = strings.Repeat("c", 64)
	r.ConfigSHA256 = r.ApplicationSHA256
	r.ControllerSHA256 = r.ApplicationSHA256
	r.ObserverSHA256 = r.ApplicationSHA256
	r.SeedSHA256 = r.ApplicationSHA256
	r.OriginalSeedSHA256 = r.ApplicationSHA256
	return r
}
func units() []Unit {
	var out []Unit
	for _, n := range Services {
		out = append(out, Unit{Name: n, LoadState: "loaded", ActiveState: "inactive", SubState: "dead", MainPID: 0, ControlPID: 0, UnitFileState: "enabled", ConditionResult: "no", DropInPaths: "/etc/systemd/system/" + n + ".d/parallel.conf"})
	}
	out[1].DropInPaths = "/etc/systemd/system/freeradius.service.d/cloud8021x.conf /etc/systemd/system/freeradius.service.d/parallel.conf"
	for _, n := range Timers {
		out = append(out, Unit{Name: n, LoadState: "loaded", ActiveState: "active", SubState: "waiting", UnitFileState: "enabled", FragmentPath: "/etc/systemd/system/" + n, Triggers: strings.TrimSuffix(n, ".timer") + ".service"})
	}
	return out
}
func sql() SQL {
	return SQL{Database: "cloud8021x_task11_green", Deployment: "task11-green", Transition: strings.Repeat("a", 64), ManifestSHA256: strings.Repeat("b", 64), Epoch: time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC), Prepared: []PreparedNode{{Role: "radius-primary", Instance: "task11-green-primary", ConfigSHA256: strings.Repeat("a", 64), ReleaseSHA256: strings.Repeat("a", 64), SourceSHA256: strings.Repeat("a", 64), Receipt: strings.Repeat("a", 32), TrustSHA256: strings.Repeat("a", 64), CertificateStateSHA256: strings.Repeat("a", 64), PolicySHA256: strings.Repeat("a", 64)}, {Role: "radius-secondary", Instance: "task11-green-secondary", ConfigSHA256: strings.Repeat("a", 64), ReleaseSHA256: strings.Repeat("a", 64), SourceSHA256: strings.Repeat("a", 64), Receipt: strings.Repeat("a", 32), TrustSHA256: strings.Repeat("a", 64), CertificateStateSHA256: strings.Repeat("a", 64), PolicySHA256: strings.Repeat("a", 64)}}, WriterFences: []Fence{{Node: "radius-primary", ConfigSHA256: strings.Repeat("a", 64), ReceiptSHA256: strings.Repeat("b", 64)}, {Node: "radius-secondary", ConfigSHA256: strings.Repeat("a", 64), ReceiptSHA256: strings.Repeat("b", 64)}}, WorkSHA256: strings.Repeat("a", 64), AttemptsSHA256: strings.Repeat("a", 64), GuardsSHA256: strings.Repeat("a", 64), AuthorizationSHA256: strings.Repeat("a", 64)}
}
func TestRequestRefusesUnenrolledOrIncompleteScope(t *testing.T) {
	if err := ValidateRequest(request()); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Request){func(r *Request) { r.Node = "blue-primary" }, func(r *Request) { r.Pin = "" }, func(r *Request) { r.BootID = "unknown" }, func(r *Request) { delete(r.Namespaces, "net") }, func(r *Request) { r.Namespaces["pid"] = "net:[123]" }, func(r *Request) { r.Phase = "active" }, func(r *Request) { r.ObserverSHA256 = "fake" }} {
		r := request()
		mutate(&r)
		if ValidateRequest(r) == nil {
			t.Error("unsafe/incomplete request accepted")
		}
	}
}
func TestManifestIndependentPinAndClosedSlots(t *testing.T) {
	r := request()
	m := Manifest{Schema: 1, OriginalSeedSHA256: r.OriginalSeedSHA256, CertificateStateSHA256: strings.Repeat("a", 64), Slots: map[string]string{}}
	for _, s := range Slots {
		m.Slots[s] = strings.Repeat("a", 64)
	}
	if err := ValidateManifest(m, r); err != nil {
		t.Fatal(err)
	}
	delete(m.Slots, "ec-root")
	if ValidateManifest(m, r) == nil {
		t.Error("missing preserved authority accepted")
	}
	m.Slots["ec-root"] = strings.Repeat("a", 64)
	m.Slots["/etc/shadow"] = strings.Repeat("a", 64)
	if ValidateManifest(m, r) == nil {
		t.Error("arbitrary path slot accepted")
	}
	delete(m.Slots, "/etc/shadow")
	m.OriginalSeedSHA256 = strings.Repeat("b", 64)
	if ValidateManifest(m, r) == nil {
		t.Error("wrong original seed accepted")
	}
}
func TestServiceActivityAndTimerGuardAreSeparate(t *testing.T) {
	if err := ValidateUnits(units(), "prepared"); err != nil {
		t.Fatal("actual guarded waiting timer refused:", err)
	}
	for _, mutate := range []func([]Unit){func(u []Unit) { u[0].MainPID = 12 }, func(u []Unit) { u[0].ActiveState = "active" }, func(u []Unit) { u[0].ControlPID = 15 }, func(u []Unit) { u[0].ConditionResult = "unavailable" }, func(u []Unit) { u[8].Triggers = "foreign.service" }, func(u []Unit) { u[8].SubState = "running" }} {
		u := units()
		mutate(u)
		if ValidateUnits(u, "prepared") == nil {
			t.Error("unsafe service/timer accepted")
		}
	}
	if ValidateUnits(units(), "deactivated") == nil {
		t.Error("deactivated live timer accepted")
	}
	if ValidateUnits(units()[:8], "prepared") == nil {
		t.Error("missing timer state accepted")
	}
}
func TestReadOnlySQLRequiresFencedDisabledKnownState(t *testing.T) {
	if err := ValidateSQL(sql(), "prepared"); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*SQL){func(s *SQL) { s.Enabled = true }, func(s *SQL) { s.WorkersAllowed = true }, func(s *SQL) { s.WriterFences = s.WriterFences[:1] }, func(s *SQL) { s.Database = "production" }, func(s *SQL) { s.Blocked = true }, func(s *SQL) { s.WorkRows = 10000 }} {
		s := sql()
		mutate(&s)
		if ValidateSQL(s, "prepared") == nil {
			t.Error("unsafe/unknown SQL accepted")
		}
	}
	if ValidateSQL(sql(), "deactivated") == nil {
		t.Error("unrevoked deactivation accepted")
	}
}
func TestSocketsRefuseWildcardIPv6AdmissionAndMutatingPeers(t *testing.T) {
	for _, s := range []Socket{{Protocol: "tcp", Local: "[::]:1812", Remote: "[::]:0", State: "0A"}, {Protocol: "udp", Local: "0.0.0.0:1813", Remote: "0.0.0.0:0", State: "07"}, {Protocol: "tcp", Local: "10.203.11.21:51000", Remote: "10.203.11.10:443", State: "01"}, {Protocol: "tcp", Local: "127.0.0.1:9080", Remote: "0.0.0.0:0", State: "0A"}} {
		if ValidateSockets([]Socket{s}, []uint16{1812, 1813, 9080}) == nil {
			t.Error("admission/outbound mutation socket accepted", s)
		}
	}
	if err := ValidateSockets([]Socket{{Protocol: "udp", Local: "127.0.0.53:53", Remote: "0.0.0.0:0", State: "07"}}, []uint16{1812, 1813}); err != nil {
		t.Fatal("bounded unrelated DNS observation refused:", err)
	}
}

func TestDeactivatedKnownWorkerMasksRequired(t *testing.T) {
	u := units()
	for i := range u {
		if WorkerMasked(u[i].Name) {
			u[i].LoadState = "masked"
			u[i].UnitFileState = "masked"
			u[i].FragmentPath = "/dev/null"
			u[i].ActiveState = "inactive"
			u[i].SubState = "dead"
			u[i].ConditionResult = ""
			u[i].DropInPaths = ""
			u[i].Triggers = ""
		}
	}
	if err := ValidateUnits(u, "deactivated"); err != nil {
		t.Fatal(err)
	}
	if ValidateUnits(u, "prepared") == nil {
		t.Fatal("masked prepared units accepted")
	}
	u[1].LoadState = "masked"
	u[1].UnitFileState = "masked"
	u[1].FragmentPath = "/dev/null"
	if ValidateUnits(u, "deactivated") == nil {
		t.Fatal("unexpected native mask accepted")
	}
}

func TestSQLRequiresTwoActualPreparedReceipts(t *testing.T) {
	s := sql()
	s.Prepared = s.Prepared[:1]
	if ValidateSQL(s, "prepared") == nil {
		t.Fatal("one physically prepared role accepted")
	}
	s = sql()
	s.Prepared[1].Role = s.Prepared[0].Role
	if ValidateSQL(s, "prepared") == nil {
		t.Fatal("duplicate role accepted")
	}
	s = sql()
	s.Prepared[0].Receipt = ""
	if ValidateSQL(s, "prepared") == nil {
		t.Fatal("missing actual preparation receipt accepted")
	}
	s = sql()
	s.Prepared[0].Ready = true
	if ValidateSQL(s, "prepared") == nil {
		t.Fatal("already activated preparation accepted")
	}
}
func TestNativeUnitRequiresItsActualTwoFixedDropins(t *testing.T) {
	u := units()
	u[1].DropInPaths = "/etc/systemd/system/freeradius.service.d/cloud8021x.conf /etc/systemd/system/freeradius.service.d/parallel.conf"
	if e := ValidateUnits(u, "prepared"); e != nil {
		t.Fatal("actual native dropins refused", e)
	}
	u[1].DropInPaths += " /run/systemd/system/freeradius.service.d/override.conf"
	if ValidateUnits(u, "prepared") == nil {
		t.Fatal("foreign native override accepted")
	}
}
func TestLastConditionResultIsNotCurrentActivationState(t *testing.T) {
	u := units()
	u[0].ConditionResult = "yes"
	if e := ValidateUnits(u, "prepared"); e != nil {
		t.Fatal("inactive guarded unit with known historical condition refused", e)
	}
	u[0].ConditionResult = "unknown"
	if ValidateUnits(u, "prepared") == nil {
		t.Fatal("unknown condition evidence accepted")
	}
}

func TestTimersRequireFixedFragmentAndNoForeignDropins(t *testing.T) {
	for _, index := range []int{len(Services), len(Services) + 1} {
		for _, inactive := range []bool{false, true} {
			u := units()
			if inactive {
				u[index].ActiveState = "inactive"
				u[index].SubState = "dead"
				u[index].UnitFileState = "disabled"
			}
			if e := ValidateUnits(u, "prepared"); e != nil {
				t.Fatal("legitimate timer state refused", e)
			}
			for _, mutation := range []func(*Unit){func(timer *Unit) { timer.DropInPaths = "/etc/systemd/system/" + timer.Name + ".d/override.conf" }, func(timer *Unit) { timer.FragmentPath = "/run/systemd/system/" + timer.Name }, func(timer *Unit) { timer.FragmentPath = "" }} {
				changed := append([]Unit(nil), u...)
				mutation(&changed[index])
				if ValidateUnits(changed, "prepared") == nil {
					t.Error("foreign/unknown effective timer accepted", index, inactive, changed[index])
				}
			}
		}
	}
}
