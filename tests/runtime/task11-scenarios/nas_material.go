package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

const nasMaterialRoot = "/var/lib/cloud8021x-task11-nas"

// Only the fixed NAS admission caller may select this root in live execution.
// Directory and UID parameters exist for pure filesystem regressions; CLI/stdin
// never supply paths, owners, or a relaxed material-name list.
func readProtectedNASMaterial(root, name, pin string, uid int) ([]byte, error) {
	if uid < 0 || !filepath.IsAbs(root) || filepath.Clean(root) != root || !slices.Contains(nasMaterialNames, name) || !shaPattern.MatchString(pin) {
		return nil, errors.New("closed canonical pinned NAS material required")
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	for _, part := range strings.Split(strings.TrimPrefix(root, "/"), "/") {
		if part == "" {
			continue
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(fd)
		if err != nil {
			return nil, errors.New("NAS material directory unavailable")
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || (int(st.Uid) != 0 && int(st.Uid) != uid) || (st.Mode&0022 != 0 && (st.Uid != 0 || st.Mode&unix.S_ISVTX == 0)) {
			_ = unix.Close(fd)
			return nil, errors.New("unsafe NAS material ancestor")
		}
	}
	defer func() { _ = unix.Close(fd) }()
	var directory unix.Stat_t
	if unix.Fstat(fd, &directory) != nil || int(directory.Uid) != uid || directory.Mode&07777 != 0700 {
		return nil, errors.New("private NAS directory owner/mode differs")
	}
	child, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("protected NAS material unavailable")
	}
	file := os.NewFile(uintptr(child), name)
	defer func() { _ = file.Close() }()
	valid := func(st unix.Stat_t) bool {
		return st.Mode&unix.S_IFMT == unix.S_IFREG && int(st.Uid) == uid && st.Mode&07777 == 0600 && st.Nlink == 1 && st.Size >= 0 && st.Size <= 64<<10
	}
	var before unix.Stat_t
	if unix.Fstat(child, &before) != nil || !valid(before) {
		return nil, errors.New("private NAS material descriptor differs")
	}
	raw, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	var after unix.Stat_t
	if err != nil || unix.Fstat(child, &after) != nil || !valid(after) || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || int64(len(raw)) != before.Size || digestBytes(raw) != pin {
		clear(raw)
		return nil, errors.New("NAS material changed/incomplete/unpinned")
	}
	return raw, nil
}
