package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func parent(path string, create bool) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 {
		return -1, errors.New("fixed canonical protected path required")
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, e
	}
	for _, n := range strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/") {
		if n == "" {
			continue
		}
		next, e := unix.Openat(fd, n, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e == unix.ENOENT && create {
			if e = unix.Mkdirat(fd, n, 0700); e == nil {
				next, e = unix.Openat(fd, n, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			}
		}
		_ = unix.Close(fd)
		if e != nil {
			return -1, errors.New("protected ancestry unavailable")
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || st.Mode&0022 != 0 {
			_ = unix.Close(fd)
			return -1, errors.New("unsafe protected ancestry")
		}
	}
	return fd, nil
}
func openPinned(path, want string, limit int64, private bool) (*os.File, error) {
	return openPinnedPolicy(path, want, limit, private, false)
}
func openPinnedPolicy(path, want string, limit int64, private, publicLower bool) (*os.File, error) {
	fd, e := parent(path, false)
	if e != nil {
		return nil, e
	}
	defer func() { _ = unix.Close(fd) }()
	leaf, e := unix.Openat(fd, filepath.Base(path), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, errors.New("protected input unavailable")
	}
	f := os.NewFile(uintptr(leaf), "protected-input")
	bad := func() (*os.File, error) {
		_ = f.Close()
		return nil, errors.New("input ownership, pin or bound differs")
	}
	var st unix.Stat_t
	if unix.Fstat(leaf, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || (!publicLower && st.Nlink != 1) || st.Nlink < 1 || st.Uid != uint32(os.Geteuid()) || st.Mode&0022 != 0 || st.Size < 0 || st.Size > limit || (private && st.Mode&0777 != 0600) {
		return bad()
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, limit+1))
	if e != nil || n > limit || hex.EncodeToString(h.Sum(nil)) != want {
		return bad()
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return bad()
	}
	return f, nil
}
func readPinned(path, want string, limit int64, private bool) ([]byte, error) {
	f, e := openPinned(path, want, limit, private)
	if e != nil {
		return nil, e
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, limit+1))
}
func publish(path string, b []byte, mode uint32) error {
	fd, e := parent(path, true)
	if e != nil {
		return e
	}
	defer func() { _ = unix.Close(fd) }()
	leaf, e := unix.Openat(fd, filepath.Base(path), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if e != nil {
		return errors.New("exclusive output refused")
	}
	f := os.NewFile(uintptr(leaf), "protected-output")
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return errors.New("private output incomplete")
	}
	if closeErr != nil {
		return closeErr
	}
	return unix.Fsync(fd)
}

func checkParentBinding(fd int, path string) error {
	current, e := parent(path, false)
	if e != nil {
		return e
	}
	defer func() { _ = unix.Close(current) }()
	var a, b unix.Stat_t
	if unix.Fstat(fd, &a) != nil || unix.Fstat(current, &b) != nil || a.Dev != b.Dev || a.Ino != b.Ino {
		return errors.New("protected destination ancestry changed")
	}
	return nil
}
func readProtected(path string, limit int64) ([]byte, error) {
	fd, e := parent(path, false)
	if e != nil {
		return nil, e
	}
	defer func() { _ = unix.Close(fd) }()
	leaf, e := unix.Openat(fd, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(leaf), "protected-generated")
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if unix.Fstat(leaf, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0022 != 0 || st.Size < 0 || st.Size > limit {
		return nil, errors.New("unsafe generated local input")
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, errors.New("generated local input exceeds bound")
	}
	return b, checkParentBinding(fd, path)
}
