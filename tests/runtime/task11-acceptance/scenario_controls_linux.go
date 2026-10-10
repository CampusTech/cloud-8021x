//go:build linux

package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/templates/systemd"

	"github.com/CampusTech/cloud-8021x/internal/adapters/freeradius/native"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
	"golang.org/x/sys/unix"
)

type linuxControlBackend struct {
	e           enrollment
	raw         []byte
	authorities map[string]controlServiceAuthority
}

func scenarioControl(ctx context.Context, e enrollment, requestRaw []byte) (scenarioControlObservation, error) {
	if ctx.Err() != nil || fixtureGuard() != nil {
		return scenarioControlObservation{}, errScenarioControl
	}
	r, err := sc.DecodeRequest(requestRaw)
	if err != nil || r.ApplicationSHA256 != e.ApplicationSHA256 {
		return scenarioControlObservation{}, errScenarioControl
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	backend := linuxControlBackend{e: e, raw: requestRaw}
	if slices.Contains([]string{"probe-active-pair", "stop-green-primary", "start-green-primary", "reboot-green-primary"}, r.Action) {
		backend.authorities, err = controlShippingAuthorities(ctx, e, r)
		if err != nil {
			return scenarioControlObservation{}, errScenarioControl
		}
	}
	return scenarioControlWith(ctx, e, r, backend)
}
func (b linuxControlBackend) Probe(ctx context.Context, n string, r sc.Request) (sc.NodeObservation, error) {
	var out sc.NodeObservation
	if n != "green-primary" && n != "green-secondary" {
		return out, errScenarioControl
	}
	m, err := inspectMachine(ctx, n, b.e)
	if err != nil {
		return out, errScenarioControl
	}
	raw, err := json.Marshal(controlProbeInput{Schema: 1, RequestBytes: b.raw, ConfigSHA256: b.e.Nodes[n].ConfigSHA256, Services: b.authorities})
	if err != nil {
		return out, errScenarioControl
	}
	defer clear(raw)
	wire, err := namespaceCall(ctx, m, []string{"scenario-probe"}, raw, 64<<10, 45*time.Second)
	defer clear(wire)
	if err != nil || decodeExactJSON(wire, &out) != nil {
		return out, errScenarioControl
	}
	after, err := inspectMachine(ctx, n, b.e)
	if err != nil || after.Leader != m.Leader || after.Start != m.Start || after.Proof.BootID != m.Proof.BootID || out.BootID != m.Proof.BootID || out.MachineID != m.Proof.MachineID || out.Leader != 1 {
		return sc.NodeObservation{}, errScenarioControl
	}
	out.Leader = m.Leader
	out.LeaderStartTicks, err = strconv.ParseUint(m.Start, 10, 64)
	if err != nil || validateControlNode(n, out, b.e) != nil {
		return sc.NodeObservation{}, errScenarioControl
	}
	return out, nil
}
func controlQueryUnit(ctx context.Context, name string, owned bool) (map[string]string, error) {
	args := []string{"/usr/bin/systemctl", "show", name, "--no-pager"}
	for _, p := range controlUnitProperties {
		args = append(args, "--property="+p)
	}
	var raw []byte
	var err error
	if owned {
		raw, err = runNamespaceBounded(ctx, args, nil, 16<<10, 10*time.Second, nil)
	} else {
		raw, err = runBounded(ctx, args, nil, 16<<10, 10*time.Second)
	}
	if err != nil {
		return nil, errScenarioControl
	}
	props, err := parseControlProperties(raw, name)
	if err != nil {
		return nil, err
	}
	for _, path := range append([]string{props["FragmentPath"]}, strings.Fields(props["DropInPaths"])...) {
		// Debian's historical /lib spelling resolves only to the fixed /usr/lib file.
		path = controlFragmentPath(path)
		data, er := controlProtectedFile(path, 0, 0644, 32<<10)
		clear(data)
		if er != nil {
			return nil, errScenarioControl
		}
	}
	return props, nil
}
func controlProcIdentity(pid int) (uint64, string, error) {
	start, err := procStart(pid)
	if err != nil {
		return 0, "", errScenarioControl
	}
	ticks, err := strconv.ParseUint(start, 10, 64)
	if err != nil || ticks == 0 {
		return 0, "", errScenarioControl
	}
	raw, err := readPublic(fmt.Sprintf("/proc/%d/cgroup", pid), 4096)
	if err != nil {
		return 0, "", errScenarioControl
	}
	line := strings.TrimSpace(string(raw))
	if strings.Contains(line, "\n") || !strings.HasPrefix(line, "0::/") {
		return 0, "", errScenarioControl
	}
	cg := strings.TrimPrefix(line, "0::")
	if filepath.Clean(cg) != cg {
		return 0, "", errScenarioControl
	}
	after, err := procStart(pid)
	if err != nil || after != start {
		return 0, "", errScenarioControl
	}
	return ticks, cg, nil
}
func (b linuxControlBackend) Unit(ctx context.Context, name string) (scenarioControlUnit, error) {
	var out scenarioControlUnit
	if name != "task11-node-green-primary.service" && name != "task11-postgres.service" {
		return out, errScenarioControl
	}
	props, err := controlQueryUnit(ctx, name, true)
	if err != nil {
		return out, err
	}
	out = scenarioControlUnit{Name: name, Active: props["ActiveState"], Sub: props["SubState"], Cgroup: props["ControlGroup"]}
	out.PID, _ = strconv.Atoi(props["MainPID"])
	if out.PID > 1 {
		var cg string
		out.Start, cg, err = controlProcIdentity(out.PID)
		if err != nil || cg != out.Cgroup {
			return out, errScenarioControl
		}
		exe, er := os.Readlink(fmt.Sprintf("/proc/%d/exe", out.PID))
		want := "/usr/bin/systemd-nspawn"
		if name == "task11-postgres.service" {
			want = "/usr/lib/postgresql/17/bin/postgres"
		}
		if er != nil || exe != want {
			return out, errScenarioControl
		}

		if controlOuterUnitIdentity(ctx, name, out.PID, b.e) != nil {
			return out, errScenarioControl
		}
		again, er := procStart(out.PID)
		if er != nil || again != strconv.FormatUint(out.Start, 10) {
			return out, errScenarioControl
		}
	}
	if out.Active == "inactive" && out.PID == 0 {
		if out.Cgroup == "" {
			out.Empty = true
		} else {
			raw, er := readPublic("/sys/fs/cgroup"+out.Cgroup+"/cgroup.events", 4096)
			if er != nil {
				return out, errScenarioControl
			}
			pop, er := operationPopulated(raw)
			if er != nil {
				return out, errScenarioControl
			}
			out.Empty = !pop
		}
	}
	return out, nil
}

type controlPIDFD struct{ fd int }

func (p *controlPIDFD) Retired() (bool, error) {
	f := []unix.PollFd{{Fd: int32(p.fd), Events: unix.POLLIN}}
	_, err := unix.Poll(f, 0)
	if err != nil || f[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
		return false, errScenarioControl
	}
	return f[0].Revents&unix.POLLIN != 0, nil
}
func (p *controlPIDFD) Close() error { return unix.Close(p.fd) }
func (b linuxControlBackend) Retain(pid int, start uint64) (scenarioControlRetirement, error) {
	before, err := procStart(pid)
	if err != nil || before != strconv.FormatUint(start, 10) {
		return nil, errScenarioControl
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, errScenarioControl
	}
	after, err := procStart(pid)
	if err != nil || after != before {
		_ = unix.Close(fd)
		return nil, errScenarioControl
	}
	return &controlPIDFD{fd: fd}, nil
}
func (b linuxControlBackend) Command(ctx context.Context, action string) error {
	var args []string
	switch action {
	case "stop-green-primary":
		args = []string{"/usr/bin/systemctl", "stop", "task11-node-green-primary.service"}
	case "start-green-primary":
		args = []string{"/usr/bin/systemctl", "start", "task11-node-green-primary.service"}
	case "reboot-green-primary":
		args = []string{"/usr/bin/machinectl", "reboot", "task11-green-primary"}
	case "stop-postgres":
		args = []string{"/usr/bin/systemctl", "stop", "task11-postgres.service"}
	case "start-postgres":
		args = []string{"/usr/bin/systemctl", "start", "task11-postgres.service"}
	case "intake-ready", "intake-unavailable":
		return cloudScenario(ctx, b.e, action, "", "")
	default:
		return errScenarioControl
	}
	raw, err := runNamespaceBounded(ctx, args, nil, 8192, 45*time.Second, nil)
	clear(raw)
	if err != nil {
		return errScenarioControl
	}
	return nil
}
func (b linuxControlBackend) Absent(ctx context.Context) error {
	raw, err := runNamespaceBounded(ctx, []string{"/usr/bin/machinectl", "list", "--no-legend", "--no-pager"}, nil, 8192, 10*time.Second, nil)
	if err != nil {
		return errScenarioControl
	}
	seen := map[string]bool{}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) > 32 {
		return errScenarioControl
	}
	for _, line := range lines {
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 || seen[f[0]] || f[0] == "task11-green-primary" {
			return errScenarioControl
		}
		seen[f[0]] = true
	}
	return nil
}
func (b linuxControlBackend) Intake(_ context.Context, _ string) (bool, error) {
	if b.e.Cloud.validate() != nil {
		return false, errScenarioControl
	}
	raw, err := readPrivate(installedAPI+"/remote-state.json", 32<<20, 0)
	defer clear(raw)
	if err != nil {
		return false, errScenarioControl
	}
	return parseControlIntake(raw, b.e.Cloud.InstalledSeedSHA256)
}
func (b linuxControlBackend) Cleanup(ctx context.Context) (sc.CleanupObservation, error) {
	return controlCleanup(ctx, b.e)
}
func (b linuxControlBackend) Pause(ctx context.Context) error {
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return errScenarioControl
	case <-timer.C:
		return nil
	}
}
func (b linuxControlBackend) Now() time.Time { return time.Now().UTC() }
func nodeScenarioProbe(ctx context.Context, in io.Reader, out io.Writer) error {
	if fixtureGuard() != nil {
		return errScenarioControl
	}
	raw, err := boundedInput(in, maxScenarioNodeInput)
	if err != nil {
		return errScenarioControl
	}
	defer clear(raw)
	cfg, manifest, err := scenarioNodeBinding(true)
	if err != nil {
		return errScenarioControl
	}
	proof, err := localProof()
	if err != nil {
		return errScenarioControl
	}
	if _, err = decodeControlProbeInput(raw, proof.Hostname, manifest.ApplicationSHA256, manifest.ConfigSHA256); err != nil {
		return err
	}
	if cfg.Bootstrap.HealthSecret.File != "/run/cloud-8021x/credentials/peer-health" || cfg.Bootstrap.ServerDNS != "radius.task11.test" || !slices.Contains([]string{"10.203.11.21", "10.203.11.22"}, cfg.Bootstrap.LocalAddress) {
		return errScenarioControl
	}
	trust, err := host.Snapshot(host.File{Path: "/etc/cloud-8021x/client-cas.pem", UID: 0})
	defer clear(trust.Data)
	if err != nil || !trust.Exists || trust.Mode != 0644 || len(trust.Data) > 1<<20 {
		return errScenarioControl
	}
	expected, err := native.ExpectedReadiness(cfg, trust.Data)
	if err != nil {
		return errScenarioControl
	}
	// Runtime credentials are deliberately owned by cloud8021x0600, rather than
	// weakening the root0600 private-control reader to accept another owner.
	user, err := host.ReadAccounts()
	if err != nil {
		return errScenarioControl
	}
	secret, err := controlProtectedFile(cfg.Bootstrap.HealthSecret.File, user.RuntimeUID, 0600, 4096)
	defer clear(secret)
	if err != nil || native.ProbeReadiness(ctx, "http://"+net.JoinHostPort(cfg.Bootstrap.LocalAddress, "18122"), []byte(strings.TrimSpace(string(secret))), expected) != nil {
		return errScenarioControl
	}
	sql, err := observeSQL(ctx, false)
	if err != nil || !sql.Enabled || sql.Blocked || sql.Ready != 2 {
		return errScenarioControl
	}
	for i := range sql.Snapshot.Work {
		clear(sql.Snapshot.Work[i].Payload)
		clear(sql.Snapshot.Work[i].Receipt)
		clear(sql.Snapshot.Work[i].AttemptReceipt)
		clear(sql.Snapshot.Work[i].RecoveryEvidence)
	}
	authorities, err := controlDecodeServices(raw)
	if err != nil || authorities["cloud-8021x.service"].ExecutableSHA256 != manifest.ApplicationSHA256 {
		return errScenarioControl
	}
	name := strings.TrimPrefix(proof.Hostname, "task11-")
	observed := sc.NodeObservation{Machine: proof.Hostname, Root: "/var/lib/cloud8021x-task11/roots/" + proof.Hostname, MachineID: proof.MachineID, BootID: proof.BootID, Leader: 1, ApplicationSHA256: manifest.ApplicationSHA256, ConfigSHA256: manifest.ConfigSHA256, Deployment: cfg.Deployment.ID, Epoch: sql.Snapshot.Epoch, WorkersActive: sql.Enabled && !sql.Blocked, WorkersBlocked: sql.Blocked, ReadyRoles: sql.Ready, Namespaces: map[string]uint64{}, Units: map[string]sc.UnitObservation{}}
	observed.LeaderStartTicks, err = controlPID1Ticks()
	if err != nil {
		return err
	}
	for n, v := range proof.Namespaces {
		prefix := n + ":["
		if !strings.HasPrefix(v, prefix) || !strings.HasSuffix(v, "]") {
			return errScenarioControl
		}
		id, er := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(v, prefix), "]"), 10, 64)
		if er != nil || id == 0 {
			return errScenarioControl
		}
		observed.Namespaces[n] = id
	}
	for _, unit := range []string{"cloud-8021x.service", "freeradius.service", "step-ca.service", "step-ca-rsa.service", "datadog-agent.service", "datadog-agent-ddot.service"} {
		u, er := controlActiveUnit(ctx, unit, authorities[unit])
		if er != nil {
			return er
		}
		observed.Units[unit] = u
	}
	observed.Collector, err = controlCollector()
	if err != nil {
		return err
	}
	// The outer namespace fills the actual host Leader and retained start ticks.
	if name != "green-primary" && name != "green-secondary" {
		return errScenarioControl
	}
	after, err := localProof()
	if err != nil || after.BootID != proof.BootID || after.MachineID != proof.MachineID || after.ConfigSHA256 != proof.ConfigSHA256 {
		return errScenarioControl
	}
	return json.NewEncoder(out).Encode(observed)
}
func controlPID1Ticks() (uint64, error) {
	v, err := procStart(1)
	if err != nil {
		return 0, errScenarioControl
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil || n == 0 {
		return 0, errScenarioControl
	}
	return n, nil
}
func controlActiveUnit(ctx context.Context, name string, authority controlServiceAuthority) (sc.UnitObservation, error) {
	var out sc.UnitObservation
	p, err := controlQueryUnit(ctx, name, false)
	if err != nil || p["ActiveState"] != "active" || p["SubState"] != "running" {
		return out, errScenarioControl
	}
	pid, _ := strconv.Atoi(p["MainPID"])
	if pid < 2 {
		return out, errScenarioControl
	}
	start, cg, err := controlProcIdentity(pid)
	if err != nil || cg != p["ControlGroup"] {
		return out, errScenarioControl
	}
	digest, err := controlProcessDigest(pid, controlServiceExecutable(name), authority.ExecutableSHA256)
	if err != nil {
		return out, errScenarioControl
	}
	files, er := controlReadUnitFiles(name)
	if er != nil || validateControlShipping(name, digest, files, authority) != nil {
		return out, errScenarioControl
	}
	for _, raw := range files {
		clear(raw)
	}
	again, er := controlQueryUnit(ctx, name, false)
	repeated, re := controlReadUnitFiles(name)
	if re != nil || validateControlShipping(name, digest, repeated, authority) != nil {
		return out, errScenarioControl
	}
	for _, raw := range repeated {
		clear(raw)
	}
	finalDigest, de := controlProcessDigest(pid, controlServiceExecutable(name), authority.ExecutableSHA256)
	after, _, pe := controlProcIdentity(pid)
	if er != nil || pe != nil || de != nil || finalDigest != digest || after != start || again["SubState"] != "running" || again["MainPID"] != p["MainPID"] || again["ControlGroup"] != cg || again["ActiveState"] != "active" {
		return out, errScenarioControl
	}
	out = sc.UnitObservation{Name: name, ActiveState: p["ActiveState"], SubState: p["SubState"], MainPID: pid, ExecutableSHA256: digest, ControlGroup: cg, ProcessCgroup: cg, FragmentPath: p["FragmentPath"], DropInPaths: strings.Fields(p["DropInPaths"])}
	return out, nil
}
func controlCollector() (sc.CollectorObservation, error) {
	raw, err := readPublic("/proc/self/mountinfo", 1<<20)
	if err != nil {
		return sc.CollectorObservation{}, errScenarioControl
	}
	out, err := parseControlCollector(raw)
	if err != nil {
		return out, err
	}
	parent, err := privateParent(out.BackingFile, 0)
	if err != nil {
		return out, errScenarioControl
	}
	defer func() { _ = unix.Close(parent) }()
	image, err := unix.Openat(parent, filepath.Base(out.BackingFile), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return out, errScenarioControl
	}
	defer func() { _ = unix.Close(image) }()
	var st unix.Stat_t
	if unix.Fstat(image, &st) != nil || st.Uid != 0 || st.Gid != 0 || st.Nlink != 1 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Size != 512<<20 {
		return out, errScenarioControl
	}
	loop, err := unix.Open(out.MountDevice, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return out, errScenarioControl
	}
	defer func() { _ = unix.Close(loop) }()
	var device unix.Stat_t
	if unix.Fstat(loop, &device) != nil || device.Mode&unix.S_IFMT != unix.S_IFBLK || unix.Major(uint64(device.Rdev)) != 7 {
		return out, errScenarioControl
	}
	info, err := unix.IoctlLoopGetStatus64(loop)
	if err != nil || info.Device != uint64(st.Dev) || info.Inode != st.Ino {
		return out, errScenarioControl
	}
	backing, err := readPublic("/sys/class/block/"+filepath.Base(out.MountDevice)+"/loop/backing_file", 4096)
	if err != nil {
		return out, errScenarioControl
	}
	// In nspawn the kernel may expose the fixed outer root prefix; ioctl identity
	// independently binds the mounted loop to this retained exact backing file.
	path := "/" + strings.TrimPrefix(strings.TrimSpace(string(backing)), "/")
	root, er := localProof()
	if er != nil || (path != out.BackingFile && path != "/var/lib/cloud8021x-task11/roots/"+root.Hostname+out.BackingFile) {
		return out, errScenarioControl
	}
	var mounted unix.Stat_t
	if unix.Stat("/var/lib/cloud8021x/collector", &mounted) != nil || mounted.Dev != device.Rdev {
		return out, errScenarioControl
	}
	var fs unix.Statfs_t
	if unix.Statfs("/var/lib/cloud8021x/collector", &fs) != nil || fs.Type != unix.EXT4_SUPER_MAGIC {
		return out, errScenarioControl
	}
	out.FileDevice, out.FileInode, out.ByteSize = uint64(st.Dev), st.Ino, uint64(st.Size)
	after, err := readPublic("/proc/self/mountinfo", 1<<20)
	if err != nil {
		return out, errScenarioControl
	}
	m, err := parseControlCollector(after)
	if err != nil || m.MountDevice != out.MountDevice || !slices.Equal(m.Options, out.Options) {
		return out, errScenarioControl
	}
	var retained, pathStat unix.Stat_t
	if unix.Fstat(image, &retained) != nil || unix.Fstatat(parent, filepath.Base(out.BackingFile), &pathStat, unix.AT_SYMLINK_NOFOLLOW) != nil || retained.Dev != st.Dev || retained.Ino != st.Ino || pathStat.Dev != st.Dev || pathStat.Ino != st.Ino {
		return out, errScenarioControl
	}
	return out, nil
}

func controlProcessDigest(pid int, path, pin string) (string, error) {
	if path == "" || !validSHA(pin) {
		return "", errScenarioControl
	}
	expected, err := controlOpenPinned(path, pin, 256<<20)
	if err != nil {
		return "", errScenarioControl
	}
	defer expected.Close()

	f, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", errScenarioControl
	}
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || st.Uid != 0 || st.Nlink != 1 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0022 != 0 || st.Mode&0111 == 0 {
		return "", errScenarioControl
	}
	before, err := f.Stat()
	want, we := expected.file.Stat()
	if err != nil || we != nil || !os.SameFile(before, want) {
		return "", errScenarioControl
	}
	digest, err := controlStreamDigest(f, 256<<20)
	if err != nil {
		return "", err
	}
	again, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", errScenarioControl
	}
	defer func() { _ = again.Close() }()
	after, err := again.Stat()
	if err != nil || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) || before.Size() != after.Size() {
		return "", errScenarioControl
	}
	if digest != pin || expected.Recheck() != nil {
		return "", errScenarioControl
	}
	return digest, nil
}

// Fixed unit names alone do not establish which guest data or network a live
// process owns. Bind the actual PostgreSQL root/net descriptors, and the actual
// registered node Leader's subtree, before allowing a lifecycle command.
func controlOuterUnitIdentity(ctx context.Context, name string, pid int, e enrollment) error {
	if name == "task11-node-green-primary.service" {
		m, err := inspectMachine(ctx, "green-primary", e)
		if err != nil {
			return errScenarioControl
		}
		_, cg, err := controlProcIdentity(m.Leader)
		parent := "/system.slice/" + name
		if err != nil || (cg != parent && !strings.HasPrefix(cg, parent+"/")) {
			return errScenarioControl
		}
		return nil
	}
	if name != "task11-postgres.service" {
		return errScenarioControl
	}
	root, err := nasOpenParent("/var/lib/cloud8021x-task11/aux/pg/check")
	if err != nil {
		return errScenarioControl
	}
	defer func() { _ = root.Close() }()
	actual, err := os.Open(fmt.Sprintf("/proc/%d/root", pid))
	if err != nil {
		return errScenarioControl
	}
	defer func() { _ = actual.Close() }()
	if !nasSameDescriptor(root, actual) {
		return errScenarioControl
	}
	parent, err := nasOpenParent("/run/netns/c11-pg")
	if err != nil {
		return errScenarioControl
	}
	defer func() { _ = parent.Close() }()
	net, err := nasOpenAt(parent, "c11-pg", false)
	if err != nil {
		return errScenarioControl
	}
	defer func() { _ = net.Close() }()
	if !nasNetworkDescriptor(net) {
		return errScenarioControl
	}
	actualNet, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		return errScenarioControl
	}
	defer func() { _ = actualNet.Close() }()
	if !nasSameDescriptor(net, actualNet) {
		return errScenarioControl
	}
	return nil
}

func controlReadUnitFiles(name string) (map[string][]byte, error) {
	out := map[string][]byte{}
	paths := controlServicePaths(name)
	if len(paths) == 0 {
		return nil, errScenarioControl
	}
	for _, path := range paths {
		raw, err := controlProtectedFile(path, 0, 0644, 32<<10)
		if err != nil {
			for _, data := range out {
				clear(data)
			}
			return nil, errScenarioControl
		}
		out[path] = raw
	}
	return out, nil
}

type controlPinnedInput struct {
	file   *os.File
	parent int
	path   string
	before unix.Stat_t
	info   os.FileInfo
}

func (f *controlPinnedInput) Close() { _ = f.file.Close(); _ = unix.Close(f.parent) }
func (f *controlPinnedInput) Recheck() error {
	var now, leaf, a, b unix.Stat_t
	current, err := privateParent(f.path, 0)
	if err != nil {
		return errScenarioControl
	}
	defer func() { _ = unix.Close(current) }()
	after, err := f.file.Stat()
	if err != nil || unix.Fstat(int(f.file.Fd()), &now) != nil || unix.Fstatat(f.parent, filepath.Base(f.path), &leaf, unix.AT_SYMLINK_NOFOLLOW) != nil || unix.Fstat(f.parent, &a) != nil || unix.Fstat(current, &b) != nil || a.Dev != b.Dev || a.Ino != b.Ino || leaf.Dev != f.before.Dev || leaf.Ino != f.before.Ino || now.Dev != f.before.Dev || now.Ino != f.before.Ino || now.Size != f.before.Size || now.Mode != f.before.Mode || now.Uid != 0 || now.Nlink != 1 || !f.info.ModTime().Equal(after.ModTime()) {
		return errScenarioControl
	}
	return nil
}
func controlOpenPinned(path, pin string, max int64) (*controlPinnedInput, error) {
	if !validSHA(pin) || max < 1 || max > 256<<20 {
		return nil, errScenarioControl
	}
	parent, err := privateParent(path, 0)
	if err != nil {
		return nil, errScenarioControl
	}
	fd, err := unix.Openat(parent, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(parent)
		return nil, errScenarioControl
	}
	f := &controlPinnedInput{file: os.NewFile(uintptr(fd), "checked-shipping-input"), parent: parent, path: path}
	fail := func() (*controlPinnedInput, error) { f.Close(); return nil, errScenarioControl }
	if unix.Fstat(fd, &f.before) != nil || f.before.Uid != 0 || f.before.Nlink != 1 || f.before.Mode&unix.S_IFMT != unix.S_IFREG || f.before.Mode&0022 != 0 || f.before.Size < 1 || f.before.Size > max {
		return fail()
	}
	f.info, err = f.file.Stat()
	if err != nil {
		return fail()
	}
	digest, err := controlStreamDigest(f.file, max)
	if err != nil || digest != pin || f.Recheck() != nil {
		return fail()
	}
	if _, err = f.file.Seek(0, 0); err != nil {
		return fail()
	}
	return f, nil
}
func controlShippingAuthorities(ctx context.Context, e enrollment, r sc.Request) (map[string]controlServiceAuthority, error) {
	// Every authority descends from the original platform inventory pinned in the
	// admitted Request. No installed executable or current unit supplies a pin.
	raw, err := readPrivate(control+"/platform-inventory.json", 1<<20, 0)
	if err != nil || adoption.Digest(raw) != r.PlatformSHA256 || scenarioValidatePlatform(raw, e, r.ScenarioSHA256) != nil {
		return nil, errScenarioControl
	}
	defer clear(raw)
	var inventory scenarioPlatformInventory
	if decodeExactJSON(raw, &inventory) != nil {
		return nil, errScenarioControl
	}
	plan, err := readPrivate(control+"/platform-plan.json", 1<<20, 0)
	if err != nil {
		return nil, errScenarioControl
	}
	defer clear(plan)
	packagePin, lowerPin, err := controlPlanAuthority(plan, inventory.PlanSHA256)
	if err != nil {
		return nil, errScenarioControl
	}
	packages, err := controlProtectedFile(control+"/public/artifacts/package-manifest.json", 0, 0644, 1<<20)
	if err != nil {
		return nil, errScenarioControl
	}
	defer clear(packages)
	archivePins, err := controlPackagePins(packages, packagePin)
	if err != nil {
		return nil, errScenarioControl
	}
	lower, err := readPrivate(control+"/lower-source.json", 32<<20, 0)
	if err != nil {
		return nil, errScenarioControl
	}
	defer clear(lower)
	xzPin, err := controlLowerXZ(lower, lowerPin)
	if err != nil {
		return nil, errScenarioControl
	}
	xz, err := controlOpenPinned("/usr/bin/xz", xzPin, 32<<20)
	if err != nil {
		return nil, errScenarioControl
	}
	defer xz.Close()
	digests := map[string]string{}
	projection := map[string][]string{"freeradius": {"/usr/sbin/freeradius", "/usr/lib/systemd/system/freeradius.service"}, "step-ca": {"/usr/bin/step-ca"}, "datadog-agent": {"/opt/datadog-agent/bin/agent/agent"}, "datadog-agent-ddot": {"/opt/datadog-agent/embedded/bin/otel-agent"}}
	for _, name := range []string{"freeradius", "step-ca", "datadog-agent", "datadog-agent-ddot"} {
		a := archivePins[name]
		path := control + "/public/artifacts/" + a.Name + "_" + a.Version + "_" + a.Architecture + ".deb"
		archive, er := controlOpenPinned(path, a.SHA256, 256<<20)
		if er != nil {
			return nil, errScenarioControl
		}
		found, er := controlArchiveProjection(ctx, archive, xz, projection[name])
		check := archive.Recheck()
		archive.Close()
		if er != nil || check != nil {
			return nil, errScenarioControl
		}
		for path, pin := range found {
			digests[path] = pin
		}
	}
	if xz.Recheck() != nil {
		return nil, errScenarioControl
	}
	rendered, err := systemd.Render()
	if err != nil {
		return nil, errScenarioControl
	}
	for _, file := range host.ParallelPassiveFiles() {
		rendered[file.Path] = file.Data
	}
	out := map[string]controlServiceAuthority{}
	for _, name := range controlShippingUnits {
		executable := digests[controlServiceExecutable(name)]
		if name == "cloud-8021x.service" {
			executable = e.ApplicationSHA256
		}
		authority := controlServiceAuthority{ExecutableSHA256: executable, Files: map[string]string{}}
		for _, path := range controlServicePaths(name) {
			if path == "/usr/lib/systemd/system/freeradius.service" {
				authority.Files[path] = digests[path]
			} else {
				data, ok := rendered[path]
				if !ok {
					return nil, errScenarioControl
				}
				authority.Files[path] = adoption.Digest(data)
			}
		}
		if validateControlAuthority(name, authority) != nil {
			return nil, errScenarioControl
		}
		out[name] = authority
	}
	return out, nil
}
func controlArchiveProjection(ctx context.Context, archive, xz *controlPinnedInput, paths []string) (map[string]string, error) {
	if archive.Recheck() != nil || xz.Recheck() != nil {
		return nil, errScenarioControl
	}
	section, kind, err := controlDebData(archive.file)
	if err != nil {
		return nil, errScenarioControl
	}
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if kind == "gz" {
		gz, er := gzip.NewReader(controlContextReader{bounded, section})
		if er != nil {
			return nil, errScenarioControl
		}
		defer func() { _ = gz.Close() }()
		return controlTarDigests(controlContextReader{bounded, gz}, paths)
	}
	if kind != "xz" {
		return nil, errScenarioControl
	}
	// The only decoder is the checked original Debian lower xz ELF. Its stdout is
	// streamed, and the exclusive operation subtree must retire before return.
	op, err := newOperationCgroup(bounded)
	if err != nil {
		return nil, errScenarioControl
	}
	cmd := exec.CommandContext(bounded, "/proc/self/fd/3", "--decompress", "--stdout", "--single-stream", "--memlimit-decompress=128MiB")
	cmd.ExtraFiles = []*os.File{xz.file}
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "HOME=/root"}
	cmd.Stdin = section
	cmd.Stderr = &boundedBuffer{limit: 4096}
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: op.fd, Setpgid: true}
	cmd.Cancel = op.kill
	cmd.WaitDelay = 3 * time.Second
	read, write, err := os.Pipe()
	if err != nil {
		_ = op.removeEmpty()
		return nil, errScenarioControl
	}
	defer func() { _ = read.Close() }()
	cmd.Stdout = write
	if err = cmd.Start(); err != nil {
		_ = write.Close()
		_ = op.removeEmpty()
		return nil, errScenarioControl
	}
	_ = write.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	readerDone := make(chan struct{})
	stopDone := make(chan struct{})
	go func() {
		defer close(stopDone)
		select {
		case <-bounded.Done():
			_ = read.Close()
		case <-readerDone:
		}
	}()
	found, parseErr := controlTarDigests(controlContextReader{bounded, read}, paths)
	close(readerDone)
	<-stopDone
	waitErr := controlDecoderWait(bounded, done, parseErr != nil, op.kill)
	controlQuiesce(op)
	releaseErr := op.removeEmpty()
	if parseErr != nil || waitErr != nil || releaseErr != nil || bounded.Err() != nil || xz.Recheck() != nil {
		return nil, errScenarioControl
	}
	return found, nil
}

func controlServiceExecutable(name string) string {
	switch name {
	case "cloud-8021x.service":
		return "/usr/local/bin/cloud-8021x"
	case "freeradius.service":
		return "/usr/sbin/freeradius"
	case "step-ca.service", "step-ca-rsa.service":
		return "/usr/bin/step-ca"
	case "datadog-agent.service":
		return "/opt/datadog-agent/bin/agent/agent"
	case "datadog-agent-ddot.service":
		return "/opt/datadog-agent/embedded/bin/otel-agent"
	default:
		return ""
	}
}

type controlContextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r controlContextReader) Read(b []byte) (int, error) {
	if r.ctx.Err() != nil {
		return 0, errScenarioControl
	}
	return r.r.Read(b)
}
