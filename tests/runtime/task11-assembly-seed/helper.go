package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/unix"
)

// Check and hash the same descriptor retained until the child has completed.
// The production caller is guest root and supplies the fixed helper path and pin.
func checkedHelper(name, want string, owner uint32) (*os.File, error) {
	parent, err := parentFD(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(parent) }()
	fd, err := unix.Openat(parent, filepath.Base(name), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != owner || st.Nlink != 1 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0022 != 0 || st.Mode&0111 == 0 || st.Size < 1 || st.Size > 32<<20 {
		_ = f.Close()
		return nil, errors.New("protected cloud helper descriptor rejected")
	}
	b, err := io.ReadAll(io.LimitReader(f, (32<<20)+1))
	matches := err == nil && len(b) <= 32<<20 && digest(b) == want
	clear(b)
	if !matches {
		_ = f.Close()
		return nil, errors.New("reviewed cloud helper pin differs")
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
func pinnedHelper() error {
	f, err := checkedHelper(cloudHelper, cloudHelperSHA, 0)
	if err != nil {
		return err
	}
	return f.Close()
}
func prepareHelper(ctx context.Context, name, want string, owner uint32, args ...string) (*exec.Cmd, *os.File, error) {
	f, err := checkedHelper(name, want, owner)
	if err != nil {
		return nil, nil, err
	}
	fdPath := "/proc/self/fd/3"
	// Darwin supports the same retained-FD regression without running the Linux helper.
	if runtime.GOOS == "darwin" {
		fdPath = "/dev/fd/3"
	}
	cmd := exec.CommandContext(ctx, fdPath, args...)
	cmd.ExtraFiles = []*os.File{f}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root"}
	return cmd, f, nil
}
func helperCommand(ctx context.Context, args ...string) ([]byte, error) {
	cmd, f, err := prepareHelper(ctx, cloudHelper, cloudHelperSHA, 0, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	out, err := cmd.Output()
	if err != nil || len(out) > 4096 {
		return nil, errors.New("fixed primitive helper refused")
	}
	return out, nil
}
