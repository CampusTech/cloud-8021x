//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func readNASMountInfo() ([]byte, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, errors.New("actual NAS mount inventory unavailable")
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	if err != nil || len(raw) > 4<<20 {
		return nil, errors.New("bounded actual NAS mount inventory unavailable")
	}
	return raw, nil
}
func openNASDirectory(path string) (*os.File, error) {
	fd, err := parent(path, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	leaf, err := unix.Openat(fd, filepath.Base(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("fixed protected NAS directory unavailable")
	}
	f := os.NewFile(uintptr(leaf), "retained-NAS-directory")
	var st unix.Stat_t
	if unix.Fstat(leaf, &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0022 != 0 || checkParentBinding(fd, path) != nil {
		_ = f.Close()
		return nil, errors.New("unsafe NAS directory")
	}
	return f, nil
}
func ensureNASProcDirectory() error {
	fd, err := parent(nasProc, false)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err = unix.Fstatat(fd, "proc", &st, unix.AT_SYMLINK_NOFOLLOW); err == unix.ENOENT {
		if err = unix.Mkdirat(fd, "proc", 0755); err != nil {
			return err
		}
		if err = unix.Fstatat(fd, "proc", &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&07777 != 0755 {
		return errors.New("preexisting NAS proc directory differs; no repair")
	}
	proc, err := openNASDirectory(nasProc)
	if err != nil {
		return err
	}
	defer func() { _ = proc.Close() }()
	entries, err := proc.ReadDir(1)
	if err != io.EOF || len(entries) != 0 {
		return errors.New("NAS proc directory is not empty")
	}
	return checkParentBinding(fd, nasProc)
}
func nasNamespaceInode(f *os.File) (uint64, error) {
	var st unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(int(f.Fd()), &st) != nil || unix.Fstatfs(int(f.Fd()), &fs) != nil || fs.Type != unix.NSFS_MAGIC || st.Ino == 0 {
		return 0, errors.New("actual NAS PID namespace absent")
	}
	kind, err := unix.IoctlRetInt(int(f.Fd()), unix.NS_GET_NSTYPE)
	if err != nil || kind != unix.CLONE_NEWPID {
		return 0, errors.New("actual NAS PID namespace type differs")
	}
	return st.Ino, nil
}
func auditNASProc() error {
	proc, err := openNASDirectory(nasProc)
	if err != nil {
		return err
	}
	defer func() { _ = proc.Close() }()
	var before, after unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(int(proc.Fd()), &before) != nil || unix.Fstatfs(int(proc.Fd()), &fs) != nil {
		return errors.New("actual NAS procfs metadata unavailable")
	}
	// Proc is an explicit outer-PID view. It is not a confinement boundary.
	nsfd, err := unix.Openat(int(proc.Fd()), "self/ns/pid", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("actual NAS procfs PID view unavailable")
	}
	ns := os.NewFile(uintptr(nsfd), "retained-NAS-proc-PID-namespace")
	defer func() { _ = ns.Close() }()
	actual, err := nasNamespaceInode(ns)
	if err != nil {
		return err
	}
	outer, err := os.Open("/proc/self/ns/pid")
	if err != nil {
		return err
	}
	defer func() { _ = outer.Close() }()
	expected, err := nasNamespaceInode(outer)
	if err != nil {
		return err
	}
	facts := nasProcFacts{Device: fmt.Sprintf("%d:%d", unix.Major(uint64(before.Dev)), unix.Minor(uint64(before.Dev))), ProcFS: fs.Type == unix.PROC_SUPER_MAGIC, ReadOnly: fs.Flags&unix.ST_RDONLY != 0, NoSuid: fs.Flags&unix.ST_NOSUID != 0, NoDev: fs.Flags&unix.ST_NODEV != 0, NoExec: fs.Flags&unix.ST_NOEXEC != 0, PIDNamespace: actual, OuterPIDNamespace: expected}
	raw, err := readNASMountInfo()
	if err != nil || validateNASProc(raw, facts) != nil {
		return errors.New("actual guarded NAS proc mount not proven")
	}
	fresh, err := openNASDirectory(nasProc)
	if err != nil {
		return err
	}
	defer func() { _ = fresh.Close() }()
	if unix.Fstat(int(fresh.Fd()), &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Uid != after.Uid {
		return errors.New("actual NAS proc mount changed")
	}
	second, err := readNASMountInfo()
	if err != nil || validateNASProc(second, facts) != nil {
		return errors.New("actual NAS proc mount recheck failed")
	}
	return nil
}
func auditNASHelpers(p plan) error {
	bindings, err := nasHelperBindings(p)
	if err != nil {
		return err
	}
	for _, binding := range bindings {
		if err = auditNASHelper(binding); err != nil {
			return err
		}
	}
	return nil
}
func auditNASHelper(binding nasHelperBinding) error {
	source, err := openPinned(binding.Source.Path, binding.Source.SHA256, 160<<20, false)
	if err != nil {
		return err
	}
	defer func() { _ = source.Close() }()
	actual, err := openPinned(binding.Target, binding.Source.SHA256, 160<<20, false)
	if err != nil {
		return err
	}
	defer func() { _ = actual.Close() }()
	sourceInfo, err := source.Stat()
	if err != nil {
		return err
	}
	actualInfo, err := actual.Stat()
	var st unix.Stat_t
	var fs unix.Statfs_t
	if err != nil || !os.SameFile(sourceInfo, actualInfo) || unix.Fstat(int(actual.Fd()), &st) != nil || st.Mode&0111 == 0 || st.Mode&07000 != 0 || unix.Fstatfs(int(actual.Fd()), &fs) != nil || fs.Flags&unix.ST_RDONLY == 0 {
		return errors.New("retained readonly NAS helper identity differs")
	}
	device := fmt.Sprintf("%d:%d", unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev)))
	raw, err := readNASMountInfo()
	if err != nil || validateNASHelperMount(raw, binding.Target, device) != nil {
		return errors.New("actual readonly NAS helper mount not proven")
	}
	fresh, err := openPinned(binding.Target, binding.Source.SHA256, 160<<20, false)
	if err != nil {
		return err
	}
	defer func() { _ = fresh.Close() }()
	rechecked, err := fresh.Stat()
	if err != nil || !os.SameFile(rechecked, actualInfo) || !actualInfo.ModTime().Equal(rechecked.ModTime()) || actualInfo.Size() != rechecked.Size() {
		return errors.New("actual NAS helper changed")
	}
	second, err := readNASMountInfo()
	if err != nil || validateNASHelperMount(second, binding.Target, device) != nil {
		return errors.New("actual NAS helper mount recheck failed")
	}
	return nil
}
func (o operation) prepareNAS() error {
	raw, err := readNASMountInfo()
	if err != nil || requireNASProcAbsent(raw) != nil {
		return errors.New("NAS proc target already mounted or uncertain")
	}
	bindings, err := nasHelperBindings(o.in.Plan)
	if err != nil {
		return err
	}
	if err = ensureNASProcDirectory(); err != nil {
		return err
	}
	for _, binding := range bindings {
		if err = o.bindPublic(binding.Source, binding.Target); err != nil {
			return err
		}
	}
	// Recheck immediately before the only fixed mount call; never repair or
	// unmount preexisting state, and retain partial effects on any failure.
	raw, err = readNASMountInfo()
	if err != nil || requireNASProcAbsent(raw) != nil {
		return errors.New("NAS proc target changed before mount")
	}
	if err = o.call("mount", nasProcArguments()...); err != nil {
		return err
	}
	return o.auditNAS()
}
func (o operation) auditNAS() error {
	if os.Geteuid() != 0 {
		return errors.New("actual Linux root NAS audit required")
	}
	if err := auditNASProc(); err != nil {
		return err
	}
	return auditNASHelpers(o.in.Plan)
}
