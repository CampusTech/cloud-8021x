package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

type controlsFake struct {
	nodes   map[string]sc.NodeObservation
	states  []scenarioControlUnit
	calls   []string
	retire  *controlsRetirement
	intake  bool
	fail    string
	cleanup sc.CleanupObservation
	after   *sc.NodeObservation
}
type controlsRetirement struct{ done, closed bool }

func (f *controlsRetirement) Retired() (bool, error) { return f.done, nil }
func (f *controlsRetirement) Close() error           { f.closed = true; return nil }
func (f *controlsFake) Probe(_ context.Context, n string, _ sc.Request) (sc.NodeObservation, error) {
	f.calls = append(f.calls, "probe:"+n)
	if f.fail == "probe" {
		return sc.NodeObservation{}, errors.New("private node details")
	}
	v := f.nodes[n]
	if f.after != nil {
		f.nodes[n] = *f.after
		f.after = nil
	}
	return v, nil
}
func (f *controlsFake) Unit(_ context.Context, n string) (scenarioControlUnit, error) {
	f.calls = append(f.calls, "unit:"+n)
	if f.fail == "unit" || len(f.states) == 0 {
		return scenarioControlUnit{}, errors.New("private unit details")
	}
	v := f.states[0]
	if len(f.states) > 1 {
		f.states = f.states[1:]
	}
	return v, nil
}
func (f *controlsFake) Retain(pid int, start uint64) (scenarioControlRetirement, error) {
	f.calls = append(f.calls, "retain")
	if f.fail == "retain" || pid < 2 || start == 0 {
		return nil, errors.New("private PID")
	}
	return f.retire, nil
}
func (f *controlsFake) Command(_ context.Context, a string) error {
	f.calls = append(f.calls, "command:"+a)
	if f.fail == "command" {
		return errors.New("private output")
	}
	return nil
}
func (f *controlsFake) Absent(context.Context) error {
	f.calls = append(f.calls, "absent")
	if f.fail == "absent" {
		return errors.New("registration remains")
	}
	return nil
}
func (f *controlsFake) Intake(_ context.Context, a string) (bool, error) {
	f.calls = append(f.calls, "intake:"+a)
	if f.fail == "intake" {
		return false, errors.New("private intake")
	}
	return f.intake, nil
}
func (f *controlsFake) Cleanup(context.Context) (sc.CleanupObservation, error) {
	f.calls = append(f.calls, "cleanup")
	if f.fail == "cleanup" {
		return sc.CleanupObservation{}, errors.New("private cleanup")
	}
	return f.cleanup, nil
}
func (f *controlsFake) Pause(ctx context.Context) error {
	if f.fail == "pause" {
		return errScenarioControl
	}
	return ctx.Err()
}
func (f *controlsFake) Now() time.Time { return time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC) }
func controlNode(n string, ordinal uint64) sc.NodeObservation {
	pin := strings.Repeat("a", 64)
	v := sc.NodeObservation{Machine: "task11-" + n, Root: "/var/lib/cloud8021x-task11/roots/task11-" + n, MachineID: strings.Repeat(string(rune('a'+ordinal)), 32), BootID: "00000000-0000-0000-0000-000000000001", Leader: int(100 + ordinal), LeaderStartTicks: ordinal, Namespaces: map[string]uint64{"mnt": ordinal + 10, "pid": ordinal + 20, "uts": ordinal + 30, "net": ordinal + 40, "cgroup": ordinal + 50}, ApplicationSHA256: pin, ConfigSHA256: pin, Deployment: "task11-green", Epoch: time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC), WorkersActive: true, ReadyRoles: 2, Units: map[string]sc.UnitObservation{}, Collector: sc.CollectorObservation{BackingFile: "/var/lib/cloud-8021x-bootstrap/collector.ext4", FileDevice: 1, FileInode: ordinal, ByteSize: 512 << 20, Filesystem: "ext4", MountDevice: "/dev/loop0", Options: []string{"rw", "nodev", "nosuid", "noexec"}, MountActive: true}}
	for _, n := range []string{"cloud-8021x.service", "freeradius.service", "step-ca.service", "step-ca-rsa.service", "datadog-agent.service", "datadog-agent-ddot.service"} {
		v.Units[n] = sc.UnitObservation{Name: n, ActiveState: "active", SubState: "running", MainPID: 200, ExecutableSHA256: pin, ControlGroup: "/system.slice/" + n, ProcessCgroup: "/system.slice/" + n, FragmentPath: "/etc/systemd/system/" + n}
	}
	return v
}
func controlFixture(action string) (enrollment, sc.Request, *controlsFake) {
	r := recordRequest(1, action)
	if strings.HasSuffix(action, "green-primary") {
		r.Node = "green-primary"
	}
	e := enrollment{ApplicationSHA256: r.ApplicationSHA256, Nodes: map[string]nodeEnrollment{}}
	f := &controlsFake{nodes: map[string]sc.NodeObservation{"green-primary": controlNode("green-primary", 1), "green-secondary": controlNode("green-secondary", 2)}, retire: &controlsRetirement{done: true}}
	for n, v := range f.nodes {
		e.Nodes[n] = nodeEnrollment{MachineID: v.MachineID, Hostname: v.Machine, ConfigSHA256: v.ConfigSHA256}
	}
	return e, r, f
}
func TestScenarioControlsObservePair(t *testing.T) {
	e, r, f := controlFixture("probe-active-pair")
	v, err := scenarioControlWith(context.Background(), e, r, f)
	if err != nil || v.Probe == nil || len(v.Probe.Nodes) != 2 {
		t.Fatalf("genuine measured pair refused: %v", err)
	}
	if !reflect.DeepEqual(f.calls, []string{"probe:green-primary", "probe:green-secondary"}) {
		t.Fatal(f.calls)
	}
}
func TestScenarioControlsRejectUnmeasuredPair(t *testing.T) {
	for _, change := range []string{"namespace", "collector", "config", "blocked", "unit", "epoch"} {
		t.Run(change, func(t *testing.T) {
			e, r, f := controlFixture("probe-active-pair")
			v := f.nodes["green-secondary"]
			switch change {
			case "namespace":
				v.Namespaces["net"] = f.nodes["green-primary"].Namespaces["net"]
			case "collector":
				v.Collector.FileInode = 1
			case "config":
				v.ConfigSHA256 = strings.Repeat("b", 64)
			case "blocked":
				v.WorkersBlocked = true
			case "unit":
				delete(v.Units, "step-ca.service")
			case "epoch":
				v.Epoch = v.Epoch.Add(time.Second)
			}
			f.nodes["green-secondary"] = v
			if _, err := scenarioControlWith(context.Background(), e, r, f); err == nil {
				t.Fatal("unbound pair accepted")
			}
		})
	}
}
func TestScenarioControlsLifecycle(t *testing.T) {
	for _, action := range []string{"stop-green-primary", "start-green-primary", "reboot-green-primary"} {
		t.Run(action, func(t *testing.T) {
			e, r, f := controlFixture(action)
			active := scenarioControlUnit{Name: "task11-node-green-primary.service", Active: "active", Sub: "running", Cgroup: "/system.slice/task11-node-green-primary.service", PID: 20, Start: 30}
			dead := scenarioControlUnit{Name: active.Name, Active: "inactive", Sub: "dead", Empty: true}
			f.states = []scenarioControlUnit{active, dead}
			if action == "start-green-primary" {
				f.states = []scenarioControlUnit{dead, active}
			}
			if action == "reboot-green-primary" {
				f.states = []scenarioControlUnit{active, active}
				v := f.nodes["green-primary"]
				v.BootID = "00000000-0000-0000-0000-000000000002"
				v.Leader++
				v.LeaderStartTicks++
				f.after = &v
			}
			v, err := scenarioControlWith(context.Background(), e, r, f)
			if err != nil || v.Lifecycle == nil || !v.Lifecycle.OldLeaderRetired {
				t.Fatalf("measured lifecycle refused: %v", err)
			}
			if action != "start-green-primary" && (!f.retire.closed || v.Lifecycle.Before == nil) {
				t.Fatal("retirement/before state missing")
			}
		})
	}
}
func TestScenarioControlsPostgresAndIntake(t *testing.T) {
	for _, action := range []string{"stop-postgres", "start-postgres", "intake-unavailable", "intake-ready"} {
		t.Run(action, func(t *testing.T) {
			e, r, f := controlFixture(action)
			active := scenarioControlUnit{Name: "task11-postgres.service", Active: "active", Sub: "running", Cgroup: "/system.slice/task11-postgres.service", PID: 40, Start: 50}
			dead := scenarioControlUnit{Name: active.Name, Active: "inactive", Sub: "dead", Empty: true}
			f.states = []scenarioControlUnit{active, dead}
			if action == "start-postgres" {
				f.states = []scenarioControlUnit{dead, active}
			}
			f.intake = action == "intake-unavailable"
			v, err := scenarioControlWith(context.Background(), e, r, f)
			if err != nil || v.Gate == nil {
				t.Fatalf("measured gate refused: %v", err)
			}
			if strings.HasPrefix(action, "intake-") && v.Gate.State != action {
				t.Fatal(v.Gate)
			}
			if action == "stop-postgres" && (!v.Gate.OldPIDRetired || !f.retire.closed) {
				t.Fatal("database retirement missing")
			}
		})
	}
}
func TestScenarioControlsErrorsStayUncertain(t *testing.T) {
	for _, failure := range []string{"unit", "retain", "command", "absent"} {
		t.Run(failure, func(t *testing.T) {
			e, r, f := controlFixture("stop-green-primary")
			f.states = []scenarioControlUnit{{Name: "task11-node-green-primary.service", Active: "active", Sub: "running", Cgroup: "/system.slice/task11-node-green-primary.service", PID: 20, Start: 30}, {Name: "task11-node-green-primary.service", Active: "inactive", Sub: "dead", Empty: true}}
			f.fail = failure
			if v, err := scenarioControlWith(context.Background(), e, r, f); err == nil || !errors.Is(err, errScenarioControl) || v.Lifecycle != nil {
				t.Fatalf("partial result/error leak: %+v %v", v, err)
			}
		})
	}
	e, r, f := controlFixture("intake-ready")
	f.intake = true
	if _, err := scenarioControlWith(context.Background(), e, r, f); err == nil {
		t.Fatal("command success substituted for actual intake state")
	}
	e, r, f = controlFixture("nas-native")
	if _, err := scenarioControlWith(context.Background(), e, r, f); err == nil || len(f.calls) != 0 {
		t.Fatal("unowned action reached backend")
	}
}

func TestScenarioControlsRetirementBeforePublishing(t *testing.T) {
	e, r, f := controlFixture("stop-postgres")
	f.states = []scenarioControlUnit{{Name: "task11-postgres.service", Active: "active", Sub: "running", Cgroup: "/system.slice/task11-postgres.service", PID: 40, Start: 50}}
	f.retire.done = false
	f.fail = "pause"
	v, err := scenarioControlWith(context.Background(), e, r, f)
	if err == nil || v.Gate != nil || !f.retire.closed {
		t.Fatal("unretired database published/handle leaked")
	}
	if !reflect.DeepEqual(f.calls, []string{"unit:task11-postgres.service", "retain", "command:stop-postgres"}) {
		t.Fatal("control retried or skipped pre-effect PID binding", f.calls)
	}
	e, r, f = controlFixture("reboot-green-primary")
	f.states = []scenarioControlUnit{{Name: "task11-node-green-primary.service", Active: "active", Sub: "running", Cgroup: "/system.slice/task11-node-green-primary.service", PID: 40, Start: 50}}
	if v, err = scenarioControlWith(context.Background(), e, r, f); err == nil || v.Lifecycle != nil {
		t.Fatal("unchanged boot substituted for reboot")
	}
}
func TestScenarioControlsEntryCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := scenarioControl(ctx, enrollment{}, nil); err == nil {
		t.Fatal("canceled control accepted")
	}
	// Entry-point references validate the portable/Linux signatures without
	// executing either a node measurement or a cleanup child in a test process.
	node := nodeScenarioProbe
	child := scenarioCleanupEntry
	if node == nil || child == nil {
		t.Fatal("closed integration entry absent")
	}
}
