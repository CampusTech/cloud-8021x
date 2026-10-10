package network

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const MaxFileBytes = 16 << 20

// privateDir resolves each directory with O_NOFOLLOW and pins the final descriptor.
// Root accepts only root-owned unwritable ancestry and the named producer's
// private directory; unprivileged callers additionally accept root sticky /tmp.
func privateDir(path string, owner int) (int, error) { return confinedDir(path, owner, true) }
func confinedDir(path string, owner int, private bool) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) == "/" || owner < 0 {
		return -1, errors.New("invalid private path")
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, e
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/")
	for i, p := range parts {
		next, e := unix.Openat(fd, p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if e != nil {
			return -1, errors.New("unsafe private path")
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil {
			_ = unix.Close(fd)
			return -1, errors.New("private directory unavailable")
		}
		safe := false
		if i == len(parts)-1 {
			safe = int(st.Uid) == owner && st.Mode&0022 == 0
			if private {
				safe = safe && st.Mode&07777 == 0700
			}
		} else {
			safe = st.Uid == 0 && st.Mode&0022 == 0
			if os.Geteuid() != 0 && owner != 0 {
				safe = safe || (int(st.Uid) == os.Geteuid() && st.Mode&0022 == 0) || (st.Uid == 0 && st.Mode&unix.S_ISVTX != 0)
			}
		}
		if !safe {
			_ = unix.Close(fd)
			return -1, errors.New("unsafe private directory ownership or mode")
		}
	}
	return fd, nil
}
func ReadPrivate(path string, owner int) ([]byte, error) { return readConfined(path, owner, true) }

// ReadPublished reads a non-secret, owner-authenticated immutable state file.
func ReadPublished(path string, owner int) ([]byte, error) { return readConfined(path, owner, false) }
func readConfined(path string, owner int, private bool) ([]byte, error) {
	mode := uint32(0644)
	if private {
		mode = 0600
	}
	dir, e := confinedDir(path, owner, private)
	if e != nil {
		return nil, e
	}
	defer func() { _ = unix.Close(dir) }()
	fd, e := unix.Openat(dir, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "private-input")
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || uint32(st.Mode)&07777 != mode || st.Nlink != 1 || int(st.Uid) != owner {
		return nil, errors.New("unsafe private input")
	}
	b, e := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if e != nil || len(b) > MaxFileBytes {
		return nil, errors.New("private input exceeds bound")
	}
	return b, nil
}
func WritePrivate(path string, b []byte) error { return writeConfined(path, b, true) }

// WritePublished never stores credentials: only successfully applied source state.
func WritePublished(path string, b []byte) error { return writeConfined(path, b, false) }
func writeConfined(path string, b []byte, private bool) error {
	mode := uint32(0644)
	if private {
		mode = 0600
	}
	if len(b) > MaxFileBytes {
		return errors.New("private output exceeds bound")
	}
	dir, e := confinedDir(path, os.Geteuid(), private)
	if e != nil {
		return e
	}
	defer func() { _ = unix.Close(dir) }()
	var st unix.Stat_t
	e = unix.Fstatat(dir, filepath.Base(path), &st, unix.AT_SYMLINK_NOFOLLOW)
	if e == nil && (st.Mode&unix.S_IFMT != unix.S_IFREG || uint32(st.Mode)&07777 != mode || st.Nlink != 1 || int(st.Uid) != os.Geteuid()) {
		return errors.New("unsafe existing output")
	}
	if e != nil && !errors.Is(e, unix.ENOENT) {
		return e
	}
	var random [16]byte
	if _, e = rand.Read(random[:]); e != nil {
		return e
	}
	name := ".network-" + hex.EncodeToString(random[:])
	fd, e := unix.Openat(dir, name, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), "private-output")
	defer func() { _ = unix.Unlinkat(dir, name, 0) }()
	e = f.Chmod(os.FileMode(mode))
	if e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	if e = unix.Renameat(dir, name, dir, filepath.Base(path)); e != nil {
		return e
	}
	return unix.Fsync(dir)
}
func RemovePrivate(path string) error   { return removeConfined(path, true) }
func RemovePublished(path string) error { return removeConfined(path, false) }
func removeConfined(path string, private bool) error {
	dir, e := confinedDir(path, os.Geteuid(), private)
	if e != nil {
		return e
	}
	defer func() { _ = unix.Close(dir) }()
	var st unix.Stat_t
	e = unix.Fstatat(dir, filepath.Base(path), &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(e, unix.ENOENT) {
		return nil
	}
	if e != nil {
		return e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || int(st.Uid) != os.Geteuid() {
		return errors.New("unsafe private removal")
	}
	if e = unix.Unlinkat(dir, filepath.Base(path), 0); e != nil {
		return e
	}
	return unix.Fsync(dir)
}

// WithPrivateLock serializes root source application across invocations. Context
// cancellation stops waiting; the lock descriptor is never replaced/unlinked.
func WithPrivateLock(ctx context.Context, path string, fn func() error) error {
	dir, e := privateDir(path, os.Geteuid())
	if e != nil {
		return e
	}
	defer func() { _ = unix.Close(dir) }()
	fd, e := unix.Openat(dir, filepath.Base(path), unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || int(st.Uid) != os.Geteuid() || st.Mode&07777 != 0600 {
		return errors.New("unsafe private lock")
	}
	for {
		e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if e == nil {
			defer func() { _ = unix.Flock(fd, unix.LOCK_UN) }()
			return fn()
		}
		if !errors.Is(e, unix.EWOULDBLOCK) {
			return e
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
