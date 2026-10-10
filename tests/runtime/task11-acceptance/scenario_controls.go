package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

var errScenarioControl = errors.New("actual owned scenario control not proven; retain claim for reconciliation")

type scenarioControlObservation struct {
	Probe     *sc.PairObservation
	Lifecycle *sc.LifecycleObservation
	Gate      *sc.GateObservation
	Cleanup   *sc.CleanupObservation
}
type scenarioControlUnit struct {
	Name, Active, Sub, Cgroup string
	PID                       int
	Start                     uint64
	Empty                     bool
}
type scenarioControlRetirement interface {
	Retired() (bool, error)
	Close() error
}
type scenarioControlBackend interface {
	Probe(context.Context, string, sc.Request) (sc.NodeObservation, error)
	Unit(context.Context, string) (scenarioControlUnit, error)
	Retain(int, uint64) (scenarioControlRetirement, error)
	Command(context.Context, string) error
	Absent(context.Context) error
	Intake(context.Context, string) (bool, error)
	Cleanup(context.Context) (sc.CleanupObservation, error)
	Pause(context.Context) error
	Now() time.Time
}

// Bodies are actual observations only. The caller retains the protected claim,
// independently rechecks physical pins, and publishes a retired Result afterward.
func scenarioControlWith(ctx context.Context, e enrollment, r sc.Request, b scenarioControlBackend) (out scenarioControlObservation, err error) {
	defer func() {
		if err != nil {
			out = scenarioControlObservation{}
			err = errScenarioControl
		}
	}()
	if b == nil || r.Validate() != nil || r.ApplicationSHA256 != e.ApplicationSHA256 || ctx.Err() != nil {
		return out, errScenarioControl
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	switch r.Action {
	case "probe-active-pair":
		pair := sc.PairObservation{Nodes: map[string]sc.NodeObservation{}}
		for _, name := range []string{"green-primary", "green-secondary"} {
			v, er := b.Probe(ctx, name, r)
			if er != nil || validateControlNode(name, v, e) != nil {
				return out, errScenarioControl
			}
			pair.Nodes[name] = v
		}
		a, z := pair.Nodes["green-primary"], pair.Nodes["green-secondary"]
		if a.MachineID == z.MachineID || a.Leader == z.Leader || (a.Collector.FileDevice == z.Collector.FileDevice && a.Collector.FileInode == z.Collector.FileInode) || !a.Epoch.Equal(z.Epoch) {
			return out, errScenarioControl
		}
		for _, name := range []string{"pid", "mnt", "uts", "net", "cgroup"} {
			if a.Namespaces[name] == z.Namespaces[name] {
				return out, errScenarioControl
			}
		}
		out.Probe = &pair
	case "stop-green-primary", "start-green-primary", "reboot-green-primary":
		v, er := controlLifecycle(ctx, e, r, b)
		if er != nil {
			return out, er
		}
		out.Lifecycle = &v
	case "stop-postgres", "start-postgres":
		v, er := controlPostgres(ctx, r.Action, b)
		if er != nil {
			return out, er
		}
		out.Gate = &v
	case "intake-unavailable", "intake-ready":
		if b.Command(ctx, r.Action) != nil {
			return out, errScenarioControl
		}
		unavailable, er := b.Intake(ctx, r.Action)
		if er != nil || unavailable != (r.Action == "intake-unavailable") {
			return out, errScenarioControl
		}
		out.Gate = &sc.GateObservation{State: r.Action, ObservedAt: b.Now().UTC()}
	case "probe-owned-cleanup":
		v, er := b.Cleanup(ctx)
		if er != nil || validateControlCleanup(v) != nil {
			return out, errScenarioControl
		}
		out.Cleanup = &v
	default:
		return out, errScenarioControl
	}
	return out, nil
}
func validateControlNode(name string, v sc.NodeObservation, e enrollment) error {
	want := e.Nodes[name]
	if v.Machine != "task11-"+name || v.Root != "/var/lib/cloud8021x-task11/roots/task11-"+name || v.MachineID != want.MachineID || v.ApplicationSHA256 != e.ApplicationSHA256 || v.ConfigSHA256 != want.ConfigSHA256 || v.BootID == "" || v.Leader < 2 || v.LeaderStartTicks == 0 || v.Deployment != "task11-green" || v.Epoch.IsZero() || !v.WorkersActive || v.WorkersBlocked || v.ReadyRoles != 2 || len(v.Namespaces) != 5 || len(v.Units) != 6 {
		return errScenarioControl
	}
	for _, n := range []string{"mnt", "pid", "uts", "net", "cgroup"} {
		if v.Namespaces[n] == 0 {
			return errScenarioControl
		}
	}
	for _, n := range []string{"cloud-8021x.service", "freeradius.service", "step-ca.service", "step-ca-rsa.service", "datadog-agent.service", "datadog-agent-ddot.service"} {
		u, ok := v.Units[n]
		if !ok || u.Name != n || u.ActiveState != "active" || u.MainPID < 2 || !validSHA(u.ExecutableSHA256) || u.ControlGroup == "" || u.ControlGroup != u.ProcessCgroup || u.FragmentPath == "" || len(u.DropInPaths) > 8 {
			return errScenarioControl
		}
	}
	c := v.Collector
	if c.BackingFile != "/var/lib/cloud-8021x-bootstrap/collector.ext4" || c.FileDevice == 0 || c.FileInode == 0 || c.ByteSize != 512<<20 || c.Filesystem != "ext4" || !c.MountActive || c.MountDevice == "" || len(c.Options) > 32 {
		return errScenarioControl
	}
	for _, n := range []string{"rw", "nodev", "nosuid", "noexec"} {
		if !slices.Contains(c.Options, n) {
			return errScenarioControl
		}
	}
	return nil
}
func controlUnitState(v scenarioControlUnit, name string, active bool) bool {
	if v.Name != name {
		return false
	}
	if !active {
		return v.Active == "inactive" && v.Sub == "dead" && v.PID == 0 && v.Empty
	}
	return v.Active == "active" && v.Sub == "running" && v.PID > 1 && v.Start > 0 && v.Cgroup == "/system.slice/"+name
}
func controlWait(ctx context.Context, b scenarioControlBackend, check func() (bool, error)) error {
	for {
		if ctx.Err() != nil {
			return errScenarioControl
		}
		ok, err := check()
		if err != nil {
			return errScenarioControl
		}
		if ok {
			return nil
		}
		if b.Pause(ctx) != nil {
			return errScenarioControl
		}
	}
}
func controlLifecycle(ctx context.Context, e enrollment, r sc.Request, b scenarioControlBackend) (sc.LifecycleObservation, error) {
	out := sc.LifecycleObservation{Unit: "task11-node-green-primary.service"}
	state, err := b.Unit(ctx, out.Unit)
	if err != nil {
		return out, errScenarioControl
	}
	var old []scenarioControlRetirement
	defer func() {
		for _, h := range old {
			_ = h.Close()
		}
	}()
	if r.Action == "start-green-primary" {
		if !controlUnitState(state, out.Unit, false) || b.Absent(ctx) != nil {
			return out, errScenarioControl
		}
	} else {
		if !controlUnitState(state, out.Unit, true) {
			return out, errScenarioControl
		}
		before, er := b.Probe(ctx, "green-primary", r)
		if er != nil || validateControlNode("green-primary", before, e) != nil {
			return out, errScenarioControl
		}
		out.Before = &before
		for _, identity := range [][2]uint64{{uint64(before.Leader), before.LeaderStartTicks}, {uint64(state.PID), state.Start}} {
			h, er := b.Retain(int(identity[0]), identity[1])
			if er != nil {
				return out, errScenarioControl
			}
			old = append(old, h)
		}
	}
	if b.Command(ctx, r.Action) != nil {
		return out, errScenarioControl
	}
	if err = controlWait(ctx, b, func() (bool, error) {
		for _, h := range old {
			done, er := h.Retired()
			if er != nil || !done {
				return false, er
			}
		}
		return true, nil
	}); err != nil {
		return out, err
	}
	out.OldLeaderRetired = true
	if r.Action == "stop-green-primary" {
		err = controlWait(ctx, b, func() (bool, error) {
			v, er := b.Unit(ctx, out.Unit)
			if er != nil {
				return false, er
			}
			if !controlUnitState(v, out.Unit, false) {
				return false, nil
			}
			if er = b.Absent(ctx); er != nil {
				return false, er
			}
			state = v
			return true, nil
		})
	} else {
		err = controlWait(ctx, b, func() (bool, error) {
			v, er := b.Unit(ctx, out.Unit)
			if er != nil {
				return false, er
			}
			if !controlUnitState(v, out.Unit, true) {
				return false, nil
			}
			after, er := b.Probe(ctx, "green-primary", r)
			if er != nil {
				return false, nil
			}
			if validateControlNode("green-primary", after, e) != nil {
				return false, errScenarioControl
			}
			if out.Before != nil && (after.BootID == out.Before.BootID || (after.Leader == out.Before.Leader && after.LeaderStartTicks == out.Before.LeaderStartTicks)) {
				return false, errScenarioControl
			}
			out.After = &after
			state = v
			return true, nil
		})
	}
	if err != nil {
		return out, err
	}
	out.UnitActiveState, out.UnitSubState = state.Active, state.Sub
	return out, nil
}
func controlPostgres(ctx context.Context, action string, b scenarioControlBackend) (sc.GateObservation, error) {
	name := "task11-postgres.service"
	out := sc.GateObservation{Unit: name}
	before, err := b.Unit(ctx, name)
	if err != nil {
		return out, errScenarioControl
	}
	var old scenarioControlRetirement
	if action == "stop-postgres" {
		if !controlUnitState(before, name, true) {
			return out, errScenarioControl
		}
		old, err = b.Retain(before.PID, before.Start)
		if err != nil {
			return out, errScenarioControl
		}
		defer func() { _ = old.Close() }()
	} else if !controlUnitState(before, name, false) {
		return out, errScenarioControl
	}
	if b.Command(ctx, action) != nil {
		return out, errScenarioControl
	}
	if old != nil {
		if err = controlWait(ctx, b, old.Retired); err != nil {
			return out, err
		}
		out.OldPIDRetired = true
	}
	var after scenarioControlUnit
	if err = controlWait(ctx, b, func() (bool, error) {
		v, er := b.Unit(ctx, name)
		if er != nil {
			return false, er
		}
		if !controlUnitState(v, name, action == "start-postgres") {
			return false, nil
		}
		after = v
		return true, nil
	}); err != nil {
		return out, err
	}
	out.State, out.MainPID, out.ObservedAt = after.Active, after.PID, b.Now().UTC()
	return out, nil
}
func validateControlCleanup(v sc.CleanupObservation) error {
	if len(v.Cases) != 2 {
		return errScenarioControl
	}
	seen := map[string]bool{}
	for _, c := range v.Cases {
		if (c.Kind != "deadline" && c.Kind != "helper-death") || seen[c.Kind] || c.Populated || !c.SentinelObservedAlive || !c.SentinelRetired || len(c.Processes) < 2 || len(c.Processes) > 8 {
			return errScenarioControl
		}
		seen[c.Kind] = true
		pids := map[int]bool{}
		for _, p := range c.Processes {
			if p.HostPID < 2 || p.StartTicks == 0 || !p.Retired || pids[p.HostPID] || !strings.HasPrefix(p.ControlGroup, "/system.slice/task11-acceptance.service/operation-") {
				return errScenarioControl
			}
			pids[p.HostPID] = true
		}
	}
	return nil
}
