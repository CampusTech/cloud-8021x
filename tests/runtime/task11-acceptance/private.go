package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Open every directory component without following links. Sticky root-owned
// ancestors (e.g. test /tmp) are safe only because all following components are
// checked too. The command always passes UID 0; unit tests use their own UID.
func privateParent(path string, uid int) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, errors.New("noncanonical private path")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/") {
		if part == "" {
			continue
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(fd)
		if e != nil {
			return -1, e
		}
		fd = next
		var st unix.Stat_t
		if e = unix.Fstat(fd, &st); e != nil || (int(st.Uid) != 0 && int(st.Uid) != uid) || (st.Mode&0022 != 0 && (st.Uid != 0 || st.Mode&unix.S_ISVTX == 0)) {
			_ = unix.Close(fd)
			return -1, errors.New("unsafe private directory owner or mode")
		}
	}
	return fd, nil
}
func fileStat(fd, uid int, limit int64) error {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != uid || st.Mode&0777 != 0600 || st.Nlink != 1 || st.Size < 0 || st.Size > limit {
		return errors.New("private file ownership, type, mode, link count or size differs")
	}
	return nil
}
func readPrivate(path string, limit int64, uid int) ([]byte, error) {
	parent, err := privateParent(path, uid)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(parent) }()
	fd, err := unix.Openat(parent, filepath.Base(path), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }()
	if err = fileStat(fd, uid, limit); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if len(raw) > int(limit) {
		return nil, errors.New("private read exceeds bound")
	}
	return raw, err
}
func atomicPrivate(path string, raw []byte, uid int) error {
	parent, err := privateParent(path, uid)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	name := filepath.Base(path)
	old, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err == nil {
		err = fileStat(old, uid, 64<<20)
		_ = unix.Close(old)
	} else if errors.Is(err, unix.ENOENT) {
		err = nil
	}
	if err != nil {
		return err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	temp := ".task11-" + hex.EncodeToString(nonce[:])
	fd, err := unix.Openat(parent, temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Unlinkat(parent, temp, 0) }()
	f := os.NewFile(uintptr(fd), temp)
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = unix.Renameat(parent, temp, parent, name); err != nil {
		return err
	}
	return unix.Fsync(parent)
}

func readPublishedSnapshot(path string, uid int) ([]byte, error) {
	parent, err := privateParent(path, uid)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(parent) }()
	fd, err := unix.Openat(parent, filepath.Base(path), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "published-snapshot")
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || int(st.Uid) != uid || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0644 || st.Nlink != 1 || st.Size < 0 || st.Size > 16<<20 {
		return nil, errors.New("published snapshot ownership or mode differs")
	}
	return boundedInput(f, 16<<20)
}
