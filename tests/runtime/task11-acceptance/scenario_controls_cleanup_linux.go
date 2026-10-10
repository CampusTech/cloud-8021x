//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// Only the fixed enrolled green-primary is entered. Namespace/root descriptors,
// physical enrollment and executable authority remain open through retirement.
// FD3 controller,4 enrollment,5 root,6..10 mnt/pid/uts/net/cgroup,11 operation,
// 12 outer proc,13 outer pid namespace,14 operation parent,15 fixed nsenter.
type controlProbeBinding struct {
	self, physical, root, outerProc, outerPID, tool *os.File
	namespaces                                      []*os.File
	parents                                         []*os.File
	leader                                          *controlPIDFD
	machine                                         machine
	enrollment                                      enrollment
	pin                                             string
	pidInode, outerInode                            uint64
}
type controlProbeMember struct {
	pid        int
	start      uint64
	cgroup     string
	namespace  uint64
	executable *os.File
	handle     *controlPIDFD
	retired    bool
}
type controlProbeProcess struct {
	cmd          *exec.Cmd
	pipe         *os.File
	done         chan error
	handle       *controlPIDFD
	cancel       context.CancelFunc
	role         string
	members      []*controlProbeMember
	helper, leaf *controlProbeMember
	finished     bool
	waitErr      error
	stopped      bool
	stopErr      error
}

func controlProbeSelf(e enrollment) (*os.File, error) {
	parent, err := nasOpenParent(helper)
	if err != nil {
		return nil, errScenarioControl
	}
	defer func() { _ = parent.Close() }()
	f, err := nasOpenAt(parent, "task11-acceptance", false)
	if err != nil {
		return nil, errScenarioControl
	}
	if nasPinnedELF(f, e.ControllerSHA256, 0) != nil || !nasCurrentSelf(f) {
		_ = f.Close()
		return nil, errScenarioControl
	}
	return f, nil
}
func controlNamespaceInode(f *os.File, kind int) (uint64, error) {
	var st unix.Stat_t
	var fs unix.Statfs_t
	if f == nil || unix.Fstat(int(f.Fd()), &st) != nil || unix.Fstatfs(int(f.Fd()), &fs) != nil || fs.Type != unix.NSFS_MAGIC || st.Ino == 0 {
		return 0, errScenarioControl
	}
	actual, err := unix.IoctlRetInt(int(f.Fd()), unix.NS_GET_NSTYPE)
	if err != nil || actual != kind {
		return 0, errScenarioControl
	}
	return st.Ino, nil
}
func controlReadPhysical(f *os.File) ([]byte, error) {
	var st unix.Stat_t
	if f == nil || unix.Fstat(int(f.Fd()), &st) != nil || st.Uid != 0 || st.Nlink != 1 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Size < 1 || st.Size > 64<<10 {
		return nil, errScenarioControl
	}
	before, err := f.Stat()
	if err != nil {
		return nil, errScenarioControl
	}
	raw, err := boundedInput(io.NewSectionReader(f, 0, (64<<10)+1), 64<<10)
	after, statErr := f.Stat()
	if err != nil || statErr != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		clear(raw)
		return nil, errScenarioControl
	}
	return raw, nil
}
func controlProcRead(proc *os.File, name string, limit int64) ([]byte, error) {
	// Following procfs's self/namespace magic links is intentional; the procfs
	// mount, not a caller-supplied pathname, fixes the outer PID interpretation.
	fd, err := unix.Openat(int(proc.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errScenarioControl
	}
	f := os.NewFile(uintptr(fd), "retained-outer-proc-record")
	defer func() { _ = f.Close() }()
	return boundedInput(f, limit)
}
func controlProcNamespace(proc *os.File, pid int) (uint64, error) {
	fd, err := unix.Openat(int(proc.Fd()), strconv.Itoa(pid)+"/ns/pid", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, errScenarioControl
	}
	f := os.NewFile(uintptr(fd), "measured-member-pid-namespace")
	defer func() { _ = f.Close() }()
	return controlNamespaceInode(f, unix.CLONE_NEWPID)
}
func controlProcExecutable(proc *os.File, pid int, expected *os.File) error {
	fd, err := unix.Openat(int(proc.Fd()), strconv.Itoa(pid)+"/exe", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return errScenarioControl
	}
	f := os.NewFile(uintptr(fd), "measured-cleanup-executable")
	defer func() { _ = f.Close() }()
	if !nasSameDescriptor(f, expected) {
		return errScenarioControl
	}
	return nil
}
func (d *controlProbeBinding) close() {
	for _, f := range append(append([]*os.File{d.self, d.physical, d.root, d.outerProc, d.outerPID, d.tool}, d.namespaces...), d.parents...) {
		if f != nil {
			_ = f.Close()
		}
	}
	if d.leader != nil {
		_ = d.leader.Close()
	}
}
func controlCaptureBinding(ctx context.Context, e enrollment) (_ *controlProbeBinding, retErr error) {
	d := &controlProbeBinding{enrollment: e}
	defer func() {
		if retErr != nil {
			d.close()
		}
	}()
	var err error
	d.machine, err = inspectMachine(ctx, "green-primary", e)
	if err != nil {
		return nil, errScenarioControl
	}
	ticks, err := strconv.ParseUint(d.machine.Start, 10, 64)
	if err != nil {
		return nil, errScenarioControl
	}
	leader, err := (linuxControlBackend{}).Retain(d.machine.Leader, ticks)
	if err != nil {
		return nil, errScenarioControl
	}
	d.leader = leader.(*controlPIDFD)
	d.self, err = controlProbeSelf(e)
	if err != nil {
		return nil, errScenarioControl
	}
	parent, err := nasOpenParent(control + "/enrollment.json")
	if err != nil {
		return nil, errScenarioControl
	}
	d.parents = append(d.parents, parent)
	d.physical, err = nasOpenAt(parent, "enrollment.json", false)
	if err != nil {
		return nil, errScenarioControl
	}
	raw, err := controlReadPhysical(d.physical)
	if err != nil {
		return nil, errScenarioControl
	}
	defer clear(raw)
	if validateScenarioPhysicalEnrollment(raw, e) != nil {
		return nil, errScenarioControl
	}
	d.pin = adoption.Digest(raw)
	d.root, err = os.Open(fmt.Sprintf("/proc/%d/root", d.machine.Leader))
	if err != nil || !nasSafeDirectory(d.root) {
		return nil, errScenarioControl
	}
	kinds := []int{unix.CLONE_NEWNS, unix.CLONE_NEWPID, unix.CLONE_NEWUTS, unix.CLONE_NEWNET, unix.CLONE_NEWCGROUP}
	for i, name := range nsNames {
		f, er := os.Open(fmt.Sprintf("/proc/%d/ns/%s", d.machine.Leader, name))
		if er != nil {
			return nil, errScenarioControl
		}
		d.namespaces = append(d.namespaces, f)
		inode, er := controlNamespaceInode(f, kinds[i])
		if er != nil || d.machine.Proof.Namespaces[name] != fmt.Sprintf("%s:[%d]", name, inode) {
			return nil, errScenarioControl
		}
		if name == "pid" {
			d.pidInode = inode
		}
	}
	d.outerPID, err = os.Open("/proc/self/ns/pid")
	if err != nil {
		return nil, errScenarioControl
	}
	d.outerInode, err = controlNamespaceInode(d.outerPID, unix.CLONE_NEWPID)
	if err != nil || d.outerInode == d.pidInode {
		return nil, errScenarioControl
	}
	d.outerProc, err = os.Open("/proc")
	var fs unix.Statfs_t
	if err != nil || !nasSafeDirectory(d.outerProc) || unix.Fstatfs(int(d.outerProc.Fd()), &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return nil, errScenarioControl
	}
	toolParent, err := nasOpenParent("/usr/bin/nsenter")
	if err != nil {
		return nil, errScenarioControl
	}
	d.parents = append(d.parents, toolParent)
	d.tool, err = nasOpenAt(toolParent, "nsenter", false)
	var toolStat unix.Stat_t
	if err != nil || unix.Fstat(int(d.tool.Fd()), &toolStat) != nil || toolStat.Uid != 0 || toolStat.Nlink != 1 || toolStat.Mode&unix.S_IFMT != unix.S_IFREG || toolStat.Mode&0022 != 0 || toolStat.Mode&07000 != 0 || toolStat.Mode&0111 == 0 {
		return nil, errScenarioControl
	}
	if d.recheck() != nil {
		return nil, errScenarioControl
	}
	return d, nil
}
func (d *controlProbeBinding) recheck() error {
	retired, err := d.leader.Retired()
	if err != nil || retired {
		return errScenarioControl
	}
	start, err := procStart(d.machine.Leader)
	if err != nil || start != d.machine.Start {
		return errScenarioControl
	}
	current, err := os.Open(fmt.Sprintf("/proc/%d/root", d.machine.Leader))
	if err != nil {
		return errScenarioControl
	}
	same := nasSameDescriptor(current, d.root)
	_ = current.Close()
	actual, err := d.root.Stat()
	expected, statErr := os.Stat(d.machine.Root)
	if !same || err != nil || statErr != nil || !os.SameFile(actual, expected) {
		return errScenarioControl
	}
	for i, name := range nsNames {
		var st unix.Stat_t
		value, er := os.Readlink(fmt.Sprintf("/proc/%d/ns/%s", d.machine.Leader, name))
		if er != nil || unix.Fstat(int(d.namespaces[i].Fd()), &st) != nil || value != fmt.Sprintf("%s:[%d]", name, st.Ino) {
			return errScenarioControl
		}
	}
	fresh, err := nasOpenAt(d.parents[0], "enrollment.json", false)
	if err != nil {
		return errScenarioControl
	}
	same = nasSameDescriptor(fresh, d.physical)
	_ = fresh.Close()
	raw, err := controlReadPhysical(d.physical)
	defer clear(raw)
	if !same || err != nil || adoption.Digest(raw) != d.pin || validateScenarioPhysicalEnrollment(raw, d.enrollment) != nil || !nasCurrentSelf(d.self) {
		return errScenarioControl
	}
	return nil
}
func controlDuplicate(fd int) (*os.File, error) {
	copyFD, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, errScenarioControl
	}
	return os.NewFile(uintptr(copyFD), "retained-operation-descriptor"), nil
}
func controlAbandonUnstarted(op *operationCgroup) (*controlProbeProcess, error) {
	// Even a failed descriptor/context admission must retain the claim until
	// this exclusive group's actual emptiness is known. Identity uncertainty
	// follows the same quarantine as a running operation.
	controlQuiesce(op)
	_ = op.removeEmpty()
	return nil, errScenarioControl
}
func controlSpawn(ctx context.Context, op *operationCgroup, d *controlProbeBinding, role string) (*controlProbeProcess, error) {
	if role != "worker" && role != "sentinel" {
		return controlAbandonUnstarted(op)
	}
	if op.bound() != nil {
		return controlAbandonUnstarted(op)
	}
	if d.recheck() != nil {
		return controlAbandonUnstarted(op)
	}
	group, err := controlDuplicate(op.fd)
	if err != nil {
		return controlAbandonUnstarted(op)
	}
	defer func() { _ = group.Close() }()
	parent, err := controlDuplicate(op.parent)
	if err != nil {
		return controlAbandonUnstarted(op)
	}
	defer func() { _ = parent.Close() }()
	child, cancel := context.WithCancel(ctx)
	argv := []string{"--mount=/proc/self/fd/6", "--pid=/proc/self/fd/7", "--uts=/proc/self/fd/8", "--net=/proc/self/fd/9", "--cgroup=/proc/self/fd/10", "--root=/proc/self/fd/5", "--wd=/proc/self/fd/5", "/proc/self/fd/3", "scenario-cleanup-child", role}
	cmd := exec.CommandContext(child, "/proc/self/fd/15", argv...)
	cmd.ExtraFiles = append([]*os.File{d.self, d.physical, d.root}, d.namespaces...)
	cmd.ExtraFiles = append(cmd.ExtraFiles, group, d.outerProc, d.outerPID, parent, d.tool)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "HOME=/root"}
	cmd.Stdin = strings.NewReader(d.pin + "\n")
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: op.fd, Setpgid: true}
	cmd.Cancel = op.kill
	cmd.WaitDelay = 3 * time.Second
	cmd.Stderr = &boundedBuffer{limit: 4096}
	r, w, err := os.Pipe()
	if err != nil {
		cancel()
		return controlAbandonUnstarted(op)
	}
	cmd.Stdout = w
	if err = cmd.Start(); err != nil {
		_ = r.Close()
		_ = w.Close()
		cancel()
		return controlAbandonUnstarted(op)
	}
	_ = w.Close()
	p := &controlProbeProcess{cmd: cmd, pipe: r, done: make(chan error, 1), cancel: cancel, role: role}
	go func() { p.done <- cmd.Wait() }()
	ticks, cg, err := controlProcIdentity(cmd.Process.Pid)
	if err == nil && cg == "/system.slice/task11-acceptance.service/"+op.name {
		h, er := (linuxControlBackend{}).Retain(cmd.Process.Pid, ticks)
		if er == nil {
			p.handle = h.(*controlPIDFD)
		} else {
			err = er
		}
	} else {
		err = errScenarioControl
	}
	if err != nil {
		cancel()
		controlQuiesce(op)
		<-p.done
		_ = r.Close()
		_ = op.removeEmpty()
		return nil, errScenarioControl
	}
	return p, nil
}
func controlReadProbeFrame(ctx context.Context, p *controlProbeProcess) (controlProbeFrame, error) {
	type frameResult struct {
		frame controlProbeFrame
		err   error
	}
	result := make(chan frameResult, 1)
	go func() {
		line, err := bufio.NewReaderSize(p.pipe, 256).ReadSlice('\n')
		frame, parseErr := parseControlProbeLine(line)
		if err != nil {
			parseErr = errScenarioControl
		}
		result <- frameResult{frame, parseErr}
	}()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		_ = p.pipe.Close()
		return controlProbeFrame{}, errScenarioControl
	case <-timer.C:
		_ = p.pipe.Close()
		return controlProbeFrame{}, errScenarioControl
	case v := <-result:
		_ = p.pipe.Close()
		return v.frame, v.err
	}
}
func controlGroupMembers(op *operationCgroup) ([]int, error) {
	if op.bound() != nil {
		return nil, errScenarioControl
	}
	fd, err := unix.Openat(op.fd, "cgroup.procs", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errScenarioControl
	}
	f := os.NewFile(uintptr(fd), "owned-cleanup-members")
	defer func() { _ = f.Close() }()
	raw, err := boundedInput(f, 4096)
	fields := strings.Fields(string(raw))
	if err != nil || len(fields) == 0 || len(fields) > 8 {
		return nil, errScenarioControl
	}
	members := make([]int, 0, len(fields))
	seen := map[int]bool{}
	for _, value := range fields {
		pid, er := parseControlPIDLine([]byte(value + "\n"))
		if er != nil || seen[pid] {
			return nil, errScenarioControl
		}
		seen[pid] = true
		members = append(members, pid)
	}
	return members, nil
}
func controlCaptureMembers(op *operationCgroup, p *controlProbeProcess, d *controlProbeBinding, frame controlProbeFrame) error {
	if (p.role == "sentinel" && frame.helper != frame.leaf) || (p.role == "worker" && frame.helper == frame.leaf) || d.recheck() != nil {
		return errScenarioControl
	}
	members, err := controlGroupMembers(op)
	if err != nil {
		return errScenarioControl
	}
	for _, pid := range members {
		start, cg, er := controlProcIdentity(pid)
		if er != nil || cg != "/system.slice/task11-acceptance.service/"+op.name {
			return errScenarioControl
		}
		h, er := (linuxControlBackend{}).Retain(pid, start)
		if er != nil {
			return errScenarioControl
		}
		member := &controlProbeMember{pid: pid, start: start, cgroup: cg, handle: h.(*controlPIDFD)}
		p.members = append(p.members, member)
		member.namespace, er = controlProcNamespace(d.outerProc, pid)
		if er != nil {
			return errScenarioControl
		}
		switch member.namespace {
		case d.pidInode:
			status, readErr := controlProcRead(d.outerProc, strconv.Itoa(pid)+"/status", 64<<10)
			host, local, mappingErr := controlPIDMapping(status)
			if readErr != nil || mappingErr != nil || validateControlNamespace(status, pid, local, d.pidInode, member.namespace, d.outerInode) != nil || host != pid {
				return errScenarioControl
			}
			member.executable = d.self
			if local == frame.helper {
				if p.helper != nil {
					return errScenarioControl
				}
				p.helper = member
			}
			if p.role == "worker" && local == frame.leaf {
				if p.leaf != nil {
					return errScenarioControl
				}
				p.leaf = member
			}
		case d.outerInode:
			// nsenter's PID-namespace monitor remains in the outer PID namespace.
			// Its real executable and every actual member are retained independently.
			member.executable = d.tool
		default:
			return errScenarioControl
		}
		if controlProcExecutable(d.outerProc, pid, member.executable) != nil {
			return errScenarioControl
		}
	}
	if p.helper == nil || (p.role == "worker" && (p.leaf == nil || p.leaf.pid == p.helper.pid)) {
		return errScenarioControl
	}
	return controlRecheckMembers(op, p, d)
}
func controlRecheckMembers(op *operationCgroup, p *controlProbeProcess, d *controlProbeBinding) error {
	if d.recheck() != nil {
		return errScenarioControl
	}
	ids, err := controlGroupMembers(op)
	if err != nil || len(ids) != len(p.members) {
		return errScenarioControl
	}
	seen := map[int]bool{}
	for _, pid := range ids {
		seen[pid] = true
	}
	for _, m := range p.members {
		done, er := m.handle.Retired()
		start, cg, identityErr := controlProcIdentity(m.pid)
		namespace, nsErr := controlProcNamespace(d.outerProc, m.pid)
		if !seen[m.pid] || er != nil || done || identityErr != nil || start != m.start || cg != m.cgroup || nsErr != nil || namespace != m.namespace || controlProcExecutable(d.outerProc, m.pid, m.executable) != nil {
			return errScenarioControl
		}
	}
	return nil
}
func controlQuiesce(op *operationCgroup) {
	warned := false
	for {
		_ = op.kill()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := awaitOperationEmpty(ctx, op.events)
		cancel()
		if err == nil {
			return
		}
		if !warned {
			logrus.WithField("operation", op.name).Error("owned cleanup probe quiescence unknown; controller quarantined")
			warned = true
		}
		time.Sleep(time.Second)
	}
}
func controlStopProbe(op *operationCgroup, p *controlProbeProcess) (err error) {
	if p.stopped {
		return p.stopErr
	}
	defer func() { p.stopped = true; p.stopErr = err }()
	controlQuiesce(op)
	p.cancel()
	if !p.finished {
		p.waitErr = <-p.done
		p.finished = true
	}
	defer func() {
		_ = p.pipe.Close()
		_ = p.handle.Close()
		for _, m := range p.members {
			_ = m.handle.Close()
		}
	}()
	done, pollErr := p.handle.Retired()
	if pollErr != nil || !done {
		return errScenarioControl
	}
	for _, m := range p.members {
		done, pollErr = m.handle.Retired()
		if pollErr != nil || !done {
			return errScenarioControl
		}
		m.retired = true
	}
	return op.removeEmpty()
}
func controlCleanup(ctx context.Context, e enrollment) (sc.CleanupObservation, error) {
	var out sc.CleanupObservation
	d, err := controlCaptureBinding(ctx, e)
	if err != nil {
		return out, err
	}
	defer d.close()
	for _, kind := range []string{"deadline", "helper-death"} {
		v, er := controlCleanupCase(ctx, d, kind)
		if er != nil || d.recheck() != nil {
			return sc.CleanupObservation{}, errScenarioControl
		}
		out.Cases = append(out.Cases, v)
	}
	return out, nil
}
func controlCleanupCase(ctx context.Context, d *controlProbeBinding, kind string) (out sc.CleanupCase, err error) {
	out.Kind = kind
	sentinelGroup, err := newOperationCgroup(ctx)
	if err != nil {
		return out, errScenarioControl
	}
	sentinel, err := controlSpawn(ctx, sentinelGroup, d, "sentinel")
	if err != nil {
		return out, err
	}
	defer func() {
		if er := controlStopProbe(sentinelGroup, sentinel); er != nil {
			err = errScenarioControl
		} else {
			out.SentinelRetired = true
		}
	}()
	sentinelFrame, err := controlReadProbeFrame(ctx, sentinel)
	if err != nil || controlCaptureMembers(sentinelGroup, sentinel, d, sentinelFrame) != nil {
		return out, errScenarioControl
	}
	op, err := newOperationCgroup(ctx)
	if err != nil {
		return out, errScenarioControl
	}
	worker, err := controlSpawn(ctx, op, d, "worker")
	if err != nil {
		return out, err
	}
	defer func() {
		if er := controlStopProbe(op, worker); er != nil {
			err = errScenarioControl
		}
	}()
	frame, err := controlReadProbeFrame(ctx, worker)
	if err != nil || controlCaptureMembers(op, worker, d, frame) != nil || controlRecheckMembers(sentinelGroup, sentinel, d) != nil {
		return out, errScenarioControl
	}
	switch kind {
	case "deadline":
		timer := time.AfterFunc(200*time.Millisecond, worker.cancel)
		defer timer.Stop()
	case "helper-death":
		// Signal the mapped actual guest helper, never the nsenter monitor PID.
		if unix.PidfdSendSignal(worker.helper.handle.fd, unix.SIGKILL, nil, 0) != nil {
			return out, errScenarioControl
		}
	default:
		return out, errScenarioControl
	}
	select {
	case runErr := <-worker.done:
		worker.waitErr = runErr
		worker.finished = true
		if runErr == nil {
			return out, errScenarioControl
		}
	case <-ctx.Done():
		return out, errScenarioControl
	}
	if er := controlStopProbe(op, worker); er != nil {
		return out, er
	}
	if controlRecheckMembers(sentinelGroup, sentinel, d) != nil {
		return out, errScenarioControl
	}
	out.SentinelObservedAlive = true
	for _, m := range worker.members {
		out.Processes = append(out.Processes, sc.ProcessObservation{HostPID: m.pid, StartTicks: m.start, ControlGroup: m.cgroup, Retired: m.retired})
	}
	// Release above required populated=0 and terminal pidfds for all measured
	// monitor/helper/leaf members, including the leaf's separate process session.
	out.Populated = false
	return out, nil
}
func controlOperationDescriptor(group, parent *os.File) error {
	var a, b unix.Stat_t
	var fs unix.Statfs_t
	if !nasSafeDirectory(group) || !nasSafeDirectory(parent) || unix.Fstatfs(int(group.Fd()), &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC || unix.Fstatfs(int(parent.Fd()), &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC || unix.Fstat(int(group.Fd()), &a) != nil {
		return errScenarioControl
	}
	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", group.Fd()))
	name := filepath.Base(path)
	if err != nil || len(name) != 42 || !strings.HasPrefix(name, "operation-") {
		return errScenarioControl
	}
	for _, c := range name[10:] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return errScenarioControl
		}
	}
	if unix.Fstatat(int(parent.Fd()), name, &b, unix.AT_SYMLINK_NOFOLLOW) != nil || a.Dev != b.Dev || a.Ino != b.Ino || b.Mode&unix.S_IFMT != unix.S_IFDIR || b.Uid != 0 {
		return errScenarioControl
	}
	return nil
}
func controlChildMembership(group, parent *os.File, role string) error {
	if controlOperationDescriptor(group, parent) != nil {
		return errScenarioControl
	}
	fd, err := unix.Openat(int(group.Fd()), "cgroup.procs", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errScenarioControl
	}
	f := os.NewFile(uintptr(fd), "guest-view-owned-cgroup-members")
	defer func() { _ = f.Close() }()
	raw, err := boundedInput(f, 4096)
	fields := strings.Fields(string(raw))
	if err != nil || len(fields) < 1 || len(fields) > 8 {
		return errScenarioControl
	}
	selfCount, parentCount := 0, 0
	for _, value := range fields {
		pid, er := strconv.Atoi(value)
		// Outer monitor PIDs may be invisible from this PID namespace. Zero is
		// never an identity claim; only the measured local helper must occur once.
		if er != nil || pid < 0 || strconv.Itoa(pid) != value {
			return errScenarioControl
		}
		if pid == os.Getpid() {
			selfCount++
		}
		if pid == os.Getppid() && pid > 1 {
			parentCount++
		}
	}
	if selfCount != 1 || (role == "leaf" && (os.Getppid() < 2 || parentCount != 1)) {
		return errScenarioControl
	}
	return controlOperationDescriptor(group, parent)
}
func controlValidateChild(files []*os.File, pin string, role string) error {
	if len(files) != 13 || !validSHA(pin) {
		return errScenarioControl
	}
	raw, err := controlReadPhysical(files[1])
	if err != nil {
		return errScenarioControl
	}
	defer clear(raw)
	var e enrollment
	if adoption.Digest(raw) != pin || decodeExactJSON(raw, &e) != nil || validateScenarioPhysicalEnrollment(raw, e) != nil || e.Schema != 1 || !validSHA(e.ControllerSHA256) || !validSHA(e.ApplicationSHA256) || len(e.Nodes) != 4 || nasPinnedELF(files[0], e.ControllerSHA256, 0) != nil || !nasCurrentSelf(files[0]) {
		return errScenarioControl
	}
	seen := map[string]bool{}
	for _, name := range nodes {
		n, ok := e.Nodes[name]
		if !ok || !machineID.MatchString(n.MachineID) || seen[n.MachineID] || n.Hostname != "task11-"+name || !validSHA(n.ConfigSHA256) {
			return errScenarioControl
		}
		seen[n.MachineID] = true
	}
	root, err := os.Open("/")
	if err != nil {
		return errScenarioControl
	}
	same := nasSameDescriptor(root, files[2])
	_ = root.Close()
	if !same {
		return errScenarioControl
	}
	proof, err := localProof()
	want := e.Nodes["green-primary"]
	if err != nil || proof.MachineID != want.MachineID || proof.Hostname != want.Hostname || proof.PID1 != "systemd" || proof.BootID == "" || proof.ApplicationSHA256 != e.ApplicationSHA256 || proof.ConfigSHA256 != want.ConfigSHA256 {
		return errScenarioControl
	}
	kinds := []int{unix.CLONE_NEWNS, unix.CLONE_NEWPID, unix.CLONE_NEWUTS, unix.CLONE_NEWNET, unix.CLONE_NEWCGROUP}
	var targetPID uint64
	for i, name := range nsNames {
		inode, er := controlNamespaceInode(files[i+3], kinds[i])
		if er != nil || proof.Namespaces[name] != fmt.Sprintf("%s:[%d]", name, inode) {
			return errScenarioControl
		}
		if name == "pid" {
			targetPID = inode
		}
	}
	outerPID, err := controlNamespaceInode(files[10], unix.CLONE_NEWPID)
	var fs unix.Statfs_t
	if err != nil || !nasSafeDirectory(files[9]) || unix.Fstatfs(int(files[9].Fd()), &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return errScenarioControl
	}
	status, err := controlProcRead(files[9], "self/status", 64<<10)
	host, local, mappingErr := controlPIDMapping(status)
	if err != nil || mappingErr != nil || local != os.Getpid() || validateControlNamespace(status, host, local, targetPID, targetPID, outerPID) != nil || controlChildMembership(files[8], files[11], role) != nil {
		return errScenarioControl
	}
	return nil
}
func scenarioCleanupEntry(ctx context.Context, args []string, out io.Writer) error {
	if fixtureGuard() != nil || len(args) != 1 || !controlCleanupRole(args[0]) || ctx.Err() != nil {
		return errScenarioControl
	}
	files := make([]*os.File, 13)
	for i := range files {
		files[i] = os.NewFile(uintptr(i+3), "inherited-cleanup-authority")
	}
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	pinRaw, err := boundedInput(os.Stdin, 65)
	defer clear(pinRaw)
	pin := strings.TrimSuffix(string(pinRaw), "\n")
	if err != nil || len(pinRaw) != 65 || controlValidateChild(files, pin, args[0]) != nil {
		return errScenarioControl
	}
	if args[0] == "worker" {
		child := exec.CommandContext(ctx, "/proc/self/fd/3", "scenario-cleanup-child", "leaf")
		child.ExtraFiles = files
		child.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "HOME=/root"}
		child.Stdin = bytes.NewReader(pinRaw)
		child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		child.Stderr = &boundedBuffer{limit: 4096}
		child.WaitDelay = 3 * time.Second
		r, w, er := os.Pipe()
		if er != nil {
			return errScenarioControl
		}
		defer func() { _ = r.Close() }()
		child.Stdout = w
		if er = child.Start(); er != nil {
			_ = w.Close()
			return errScenarioControl
		}
		_ = w.Close()
		defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
		line, er := bufio.NewReaderSize(r, 256).ReadSlice('\n')
		pid, parseErr := parseControlPIDLine(line)
		if er != nil || parseErr != nil || pid != child.Process.Pid || controlChildMembership(files[8], files[11], "worker") != nil {
			return errScenarioControl
		}
		if _, er = fmt.Fprintln(out, os.Getpid(), pid); er != nil {
			return errScenarioControl
		}
	} else if args[0] == "sentinel" {
		if _, err = fmt.Fprintln(out, os.Getpid(), os.Getpid()); err != nil {
			return errScenarioControl
		}
	} else if _, err = fmt.Fprintln(out, os.Getpid()); err != nil {
		return errScenarioControl
	}
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return errScenarioControl
	case <-timer.C:
		return errScenarioControl
	}
}
