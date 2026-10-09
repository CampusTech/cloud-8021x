//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const nasNet = "/run/netns/c11-nas"

func nasDescriptorCall(ctx context.Context, e enrollment, scenarioSHA, action string, input []byte) ([]byte, error) {
	if _, err := nasTransportInvocation(e, scenarioSHA, action, len(input)); err != nil || ctx.Err() != nil || fixtureGuard() != nil {
		return nil, errNASTransport
	}
	return runNASDescriptor(ctx, e, scenarioSHA, action, input, captureNASDescriptors, runNamespaceBounded)
}
func nasSafeDirectory(f *os.File) bool {
	var st unix.Stat_t
	return f != nil && unix.Fstat(int(f.Fd()), &st) == nil && st.Uid == 0 && st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Mode&0022 == 0
}
func nasSameDescriptor(a, b *os.File) bool {
	var x, y unix.Stat_t
	return a != nil && b != nil && unix.Fstat(int(a.Fd()), &x) == nil && unix.Fstat(int(b.Fd()), &y) == nil && x.Dev == y.Dev && x.Ino == y.Ino && x.Mode == y.Mode && x.Uid == y.Uid && x.Nlink == y.Nlink
}
func nasOpenAt(parent *os.File, name string, directory bool) (*os.File, error) {
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Openat(int(parent.Fd()), name, flags, 0)
	if err != nil {
		return nil, errNASTransport
	}
	f := os.NewFile(uintptr(fd), "fixed-nas-descriptor")
	if directory && !nasSafeDirectory(f) {
		_ = f.Close()
		return nil, errNASTransport
	}
	return f, nil
}
func nasOpenParent(path string) (*os.File, error) {
	fd, err := privateParent(path, 0)
	if err != nil {
		return nil, errNASTransport
	}
	f := os.NewFile(uintptr(fd), "fixed-nas-parent")
	if !nasSafeDirectory(f) {
		_ = f.Close()
		return nil, errNASTransport
	}
	return f, nil
}
func nasHelperBelow(root *os.File) (*os.File, []*os.File, error) {
	parents := []*os.File{}
	at := root
	for _, part := range []string{"usr", "local", "libexec"} {
		f, err := nasOpenAt(at, part, true)
		if err != nil {
			for _, p := range parents {
				_ = p.Close()
			}
			return nil, nil, err
		}
		parents = append(parents, f)
		at = f
	}
	f, err := nasOpenAt(at, "task11-scenarios", false)
	return f, parents, err
}
func nasNetworkDescriptor(f *os.File) bool {
	var st unix.Stat_t
	var fs unix.Statfs_t
	if f == nil || unix.Fstat(int(f.Fd()), &st) != nil || st.Uid != 0 || st.Nlink != 1 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0022 != 0 || unix.Fstatfs(int(f.Fd()), &fs) != nil || fs.Type != unix.NSFS_MAGIC {
		return false
	}
	typ, err := unix.IoctlRetInt(int(f.Fd()), unix.NS_GET_NSTYPE)
	if err != nil || typ != unix.CLONE_NEWNET {
		return false
	}
	outer, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return false
	}
	defer func() { _ = outer.Close() }()
	return !nasSameDescriptor(f, outer)
}
func nasProcDescriptor(f *os.File) (nasProcIdentity, error) {
	var st unix.Stat_t
	var fs unix.Statfs_t
	if !nasSafeDirectory(f) || unix.Fstat(int(f.Fd()), &st) != nil || unix.Fstatfs(int(f.Fd()), &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC || fs.Flags&unix.ST_RDONLY == 0 || fs.Flags&unix.ST_NOSUID == 0 || fs.Flags&unix.ST_NODEV == 0 {
		return nasProcIdentity{}, errNASTransport
	}
	raw, err := readPublic("/proc/self/mountinfo", 256<<10)
	if err != nil {
		return nasProcIdentity{}, errNASTransport
	}
	device := fmt.Sprintf("%d:%d", unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev)))
	return nasProcMountIdentity(raw, device)
}
func nasCurrentSelf(f *os.File) bool {
	actual, err := os.Open("/proc/self/exe")
	if err != nil {
		return false
	}
	defer func() { _ = actual.Close() }()
	return nasSameDescriptor(actual, f)
}

// Procfs is an explicit synthetic-guest assembly prerequisite. The helper does
// not create/repair mounts. Read-only procfs is not a confinement boundary.
func captureNASDescriptors(e enrollment, pin string) (_ *nasDescriptors, retErr error) {
	d := &nasDescriptors{}
	defer func() {
		if retErr != nil {
			d.close()
		}
	}()
	rootParent, err := nasOpenParent(nasRoot)
	if err != nil {
		return nil, err
	}
	d.held = append(d.held, rootParent)
	root, err := nasOpenAt(rootParent, filepath.Base(nasRoot), true)
	if err != nil {
		return nil, err
	}
	d.files = append(d.files, root)
	netParent, err := nasOpenParent(nasNet)
	if err != nil {
		return nil, err
	}
	d.held = append(d.held, netParent)
	net, err := nasOpenAt(netParent, filepath.Base(nasNet), false)
	if err != nil {
		return nil, err
	}
	d.files = append(d.files, net)
	if !nasNetworkDescriptor(net) {
		return nil, errNASTransport
	}
	program, parents, err := nasHelperBelow(root)
	d.held = append(d.held, parents...)
	if err != nil {
		return nil, err
	}
	d.files = append(d.files, program)
	selfParent, err := nasOpenParent(helper)
	if err != nil {
		return nil, err
	}
	d.held = append(d.held, selfParent)
	self, err := nasOpenAt(selfParent, filepath.Base(helper), false)
	if err != nil {
		return nil, err
	}
	d.files = append(d.files, self)
	if nasPinnedELF(program, pin, 0) != nil || nasPinnedELF(self, e.ControllerSHA256, 0) != nil || !nasCurrentSelf(self) {
		return nil, errNASTransport
	}
	proc, err := nasOpenAt(root, "proc", true)
	if err != nil {
		return nil, err
	}
	d.held = append(d.held, proc)
	procIdentity, err := nasProcDescriptor(proc)
	if err != nil {
		return nil, err
	}
	d.recheck = func() error {
		for i, path := range []string{nasRoot, nasNet, helper} {
			fresh, err := nasOpenParent(path)
			if err != nil {
				return err
			}
			old := []*os.File{rootParent, netParent, selfParent}[i]
			same := nasSameDescriptor(old, fresh)
			_ = fresh.Close()
			if !same {
				return errNASTransport
			}
		}
		for _, item := range []struct {
			parent, file *os.File
			name         string
			directory    bool
		}{{rootParent, root, filepath.Base(nasRoot), true}, {netParent, net, filepath.Base(nasNet), false}, {selfParent, self, filepath.Base(helper), false}, {root, proc, "proc", true}} {
			fresh, err := nasOpenAt(item.parent, item.name, item.directory)
			if err != nil {
				return err
			}
			same := nasSameDescriptor(item.file, fresh)
			_ = fresh.Close()
			if !same {
				return errNASTransport
			}
		}
		fresh, freshParents, err := nasHelperBelow(root)
		defer func() {
			if fresh != nil {
				_ = fresh.Close()
			}
			for _, p := range freshParents {
				_ = p.Close()
			}
		}()
		if err != nil || len(freshParents) != len(parents) || !nasSameDescriptor(program, fresh) {
			return errNASTransport
		}
		for i := range parents {
			if !nasSafeDirectory(parents[i]) || !nasSameDescriptor(parents[i], freshParents[i]) {
				return errNASTransport
			}
		}
		current, err := nasProcDescriptor(proc)
		if err != nil || current != procIdentity || !nasNetworkDescriptor(net) || nasPinnedELF(program, pin, 0) != nil || nasPinnedELF(self, e.ControllerSHA256, 0) != nil || !nasCurrentSelf(self) {
			return errNASTransport
		}
		return nil
	}
	if d.recheck() != nil {
		return nil, errNASTransport
	}
	return d, nil
}
func nasChildOperation() error {
	raw, err := readPublic("/proc/self/cgroup", 4096)
	if err != nil {
		return errNASTransport
	}
	path, err := nasOperationPath(raw)
	if err != nil {
		return err
	}
	parent, err := nasOpenParent("/sys/fs/cgroup" + path + "/cgroup.procs")
	if err != nil {
		return err
	}
	defer func() { _ = parent.Close() }()
	var fs unix.Statfs_t
	if unix.Fstatfs(int(parent.Fd()), &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return errNASTransport
	}
	parentRaw, err := readPublic(fmt.Sprintf("/proc/%d/cgroup", os.Getppid()), 4096)
	if err != nil || strings.TrimSuffix(string(parentRaw), "\n") != "0::/system.slice/task11-acceptance.service" {
		return errNASTransport
	}
	members, err := readPublic("/sys/fs/cgroup"+path+"/cgroup.procs", 64<<10)
	if err != nil {
		return errNASTransport
	}
	count := 0
	for _, pid := range strings.Fields(string(members)) {
		if !nasDecimal(pid, true) {
			return errNASTransport
		}
		if pid == strconv.Itoa(os.Getpid()) {
			count++
		}
	}
	if count != 1 {
		return errNASTransport
	}
	return nil
}
func nasDescriptorEntry(ctx context.Context, args []string) error {
	action, pin, err := nasEntryArguments(args)
	if err != nil || ctx.Err() != nil || fixtureGuard() != nil || nasChildOperation() != nil {
		return errNASTransport
	}
	e, err := loadEnrollment()
	if err != nil {
		return errNASTransport
	}
	d, err := captureNASDescriptors(e, pin)
	if err != nil {
		return errNASTransport
	}
	defer d.close()
	inherited := make([]*os.File, 4)
	defer func() {
		for _, f := range inherited {
			if f != nil {
				_ = f.Close()
			}
		}
	}()
	for i, actual := range d.files {
		inherited[i] = os.NewFile(uintptr(i+3), "inherited-nas-role")
		if !nasSameDescriptor(actual, inherited[i]) {
			return errNASTransport
		}
	}
	if d.recheck() != nil || ctx.Err() != nil {
		return errNASTransport
	}
	argv, err := nasHelperArguments(action)
	if err != nil {
		return err
	}
	env := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "HOME=/root"}
	// This terminal child never returns after changing thread namespaces/root.
	// Exported syscall.Exec provides Go's exec/thread-creation serialization.
	runtime.LockOSThread()
	if unix.Unshare(unix.CLONE_FS) == nil && unix.CloseRange(3, uint(^uint32(0)), unix.CLOSE_RANGE_CLOEXEC) == nil && unix.Setns(4, unix.CLONE_NEWNET) == nil && unix.Fchdir(3) == nil && unix.Chroot(".") == nil && unix.Chdir("/") == nil {
		_ = syscall.Exec("/proc/self/fd/5", argv, env)
	}
	os.Exit(127)
	return errNASTransport // unreachable; keeps the error-returning API explicit.
}
