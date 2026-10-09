//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// Only outer namespace operations use these groups. Entering a PID/cgroup
// namespace does not change actual membership; Setpgid also cannot escape it.
// PID1-created business services are prior side effects, not descendants of this
// command group, and are reconciled using the product's actual protected state.
type operationCgroup struct {
	fd, parent    int
	name          string
	device, inode uint64
}

func controllerGroup(ctx context.Context) (string, error) {
	raw, err := readPublic("/proc/self/cgroup", 4096)
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(raw))
	if strings.Contains(line, "\n") || !strings.HasPrefix(line, "0::/") {
		return "", errors.New("unified controller cgroup required")
	}
	path := strings.TrimPrefix(line, "0::")
	if filepath.Clean(path) != path || !strings.HasPrefix(path, "/system.slice/") {
		return "", errors.New("controller must run in the fixed outer systemd service")
	}
	unit := "task11-acceptance.service"
	if path != "/system.slice/"+unit {
		return "", errors.New("single fixed controller service required")
	}
	out, err := runBounded(ctx, []string{"/usr/bin/systemctl", "show", unit, "--property=ControlGroup", "--property=MainPID", "--property=Delegate", "--property=KillMode", "--property=SendSIGKILL"}, nil, 8192, 15*time.Second)
	if err != nil {
		return "", err
	}
	props := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok || props[k] != "" {
			return "", errors.New("ambiguous controller service evidence")
		}
		props[k] = v
	}
	if props["ControlGroup"] != path || props["MainPID"] != strconv.Itoa(os.Getpid()) || props["Delegate"] != "yes" || props["KillMode"] != "control-group" || props["SendSIGKILL"] != "yes" {
		return "", errors.New("delegated PID1 controller cleanup contract missing")
	}
	return "/sys/fs/cgroup" + path, nil
}
func newOperationCgroup(ctx context.Context) (*operationCgroup, error) {
	path, err := controllerGroup(ctx)
	if err != nil {
		return nil, err
	}
	parent, err := privateParent(path+"/owned-operation", 0)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (*operationCgroup, error) { _ = unix.Close(parent); return nil, e }
	var fs unix.Statfs_t
	if unix.Fstatfs(parent, &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return fail(errors.New("real cgroup-v2 delegation required"))
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return fail(err)
	}
	name := "operation-" + hex.EncodeToString(nonce[:])
	if err = unix.Mkdirat(parent, name, 0755); err != nil {
		return fail(err)
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Unlinkat(parent, name, unix.AT_REMOVEDIR)
		return fail(err)
	}
	op := &operationCgroup{fd: fd, parent: parent, name: name}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&0022 != 0 {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(parent, name, unix.AT_REMOVEDIR)
		return fail(errors.New("operation cgroup owner differs"))
	}
	op.device, op.inode = uint64(st.Dev), st.Ino
	// Refuse unsupported kernel/delegation BEFORE creating any operation process.
	kill, err := unix.Openat(fd, "cgroup.kill", unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err == nil {
		_ = unix.Close(kill)
	}
	if err != nil {
		_ = op.removeEmpty()
		return nil, errors.New("atomic cgroup subtree kill unavailable")
	}
	raw, err := op.events()
	if err == nil {
		var populated bool
		populated, err = operationPopulated(raw)
		if populated {
			err = errors.New("new exclusive operation group is populated")
		}
	}
	if err != nil {
		_ = op.removeEmpty()
		return nil, err
	}
	return op, nil
}
func (o *operationCgroup) bound() error {
	var a, b unix.Stat_t
	if unix.Fstat(o.fd, &a) != nil || unix.Fstatat(o.parent, o.name, &b, unix.AT_SYMLINK_NOFOLLOW) != nil || uint64(a.Dev) != o.device || a.Ino != o.inode || uint64(b.Dev) != o.device || b.Ino != o.inode || a.Uid != 0 || b.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("owned operation cgroup identity changed")
	}
	return nil
}
func (o *operationCgroup) events() ([]byte, error) {
	if err := o.bound(); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(o.fd, "cgroup.events", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "owned-cgroup-events")
	defer func() { _ = f.Close() }()
	return boundedInput(f, 4096)
}
func (o *operationCgroup) kill() error {
	if err := o.bound(); err != nil {
		return err
	}
	fd, err := unix.Openat(o.fd, "cgroup.kill", unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	n, err := unix.Write(fd, []byte("1"))
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("short operation kill")
	}
	return nil
}
func (o *operationCgroup) removeEmpty() error {
	raw, err := o.events()
	if err != nil {
		return err
	}
	populated, err := operationPopulated(raw)
	if err != nil {
		return err
	}
	if populated {
		return errors.New("cannot release populated operation")
	}
	if err = unix.Unlinkat(o.parent, o.name, unix.AT_REMOVEDIR); err != nil {
		return err
	}
	a, b := unix.Close(o.fd), unix.Close(o.parent)
	return errors.Join(a, b)
}
func runNamespaceBounded(ctx context.Context, argv []string, input []byte, limit int, timeout time.Duration, files []*os.File) ([]byte, error) {
	op, err := newOperationCgroup(ctx)
	if err != nil {
		return nil, err
	}
	out, runErr := runBoundedConfigured(ctx, argv, input, limit, timeout, files, func(cmd *exec.Cmd) {
		cmd.SysProcAttr.UseCgroupFD = true
		cmd.SysProcAttr.CgroupFD = op.fd
		cmd.Cancel = op.kill
	})
	raw, readErr := op.events()
	populated, popErr := operationPopulated(raw)
	if runErr == nil && (readErr != nil || popErr != nil || populated) {
		runErr = errors.New("namespace helper left uncertain descendants; reconcile prior product side effects")
	}
	warned := false
	for {
		_ = op.kill()
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err = awaitOperationEmpty(cleanup, op.events)
		cancel()
		if err == nil {
			break
		}
		// Unknown quiescence MUST NOT release the stage flock. Keep the controller
		// and bound descriptors alive; stopping this fixed unit delegates its whole
		// cgroup cleanup to PID1. This is a quarantine, not a successful timeout.
		if !warned {
			logrus.WithField("operation", op.name).Error("owned operation quiescence unknown; controller quarantined for reconciliation")
			warned = true
		}
		time.Sleep(time.Second)
	}
	if err = op.removeEmpty(); err != nil {
		return nil, fmt.Errorf("empty operation cleanup: %w", err)
	}
	if runErr != nil {
		clear(out)
		return nil, runErr
	}
	return out, nil
}
