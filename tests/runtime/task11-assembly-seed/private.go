package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const maxPrivate = 4 << 20

// All ancestors are opened without symlink following. Sticky root-owned /tmp
// is permitted for local unit tests; production uses the fixed guest control tree.
func parentFD(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, errors.New("noncanonical private path")
	}
	fd, err := unix.Open("/", unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/") {
		if part == "" {
			continue
		}
		next, e := unix.Openat(fd, part, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(fd)
		if e != nil {
			return -1, e
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || (st.Mode&0022 != 0 && (st.Uid != 0 || st.Mode&unix.S_ISVTX == 0)) {
			_ = unix.Close(fd)
			return -1, errors.New("unsafe private directory")
		}
	}
	return fd, nil
}
func privateOpen(path string, flags int) (*os.File, error) {
	parent, err := parentFD(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(parent) }()
	fd, err := unix.Openat(parent, filepath.Base(path), flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) {
		_ = f.Close()
		return nil, errors.New("private file ownership/mode/link rejected")
	}
	return f, nil
}
func readPrivate(path string) ([]byte, error) {
	f, err := privateOpen(path, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxPrivate+1))
	if err != nil || len(b) > maxPrivate {
		return nil, errors.New("bounded private file required")
	}
	return b, nil
}
func writeExclusive(path string, b []byte) error {
	if len(b) > maxPrivate {
		return errors.New("private output bound exceeded")
	}
	f, err := privateOpen(path, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	p, err := parentFD(path)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(p) }()
	return unix.Fsync(p)
}
func replaceOriginal(path string, b []byte) error {
	// Only the two explicitly reviewed seed/manifest paths call this function.
	if _, err := readPrivate(path); err != nil {
		return err
	}
	temp := path + ".assembly-next"
	if err := writeExclusive(temp, b); err != nil {
		return err
	}
	parent, err := parentFD(path)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	if err = unix.Renameat(parent, filepath.Base(temp), parent, filepath.Base(path)); err != nil {
		return err
	}
	return unix.Fsync(parent)
}
func mkdirPrivate(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	fd, err := parentFD(filepath.Join(path, "probe"))
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&0777 != 0700 || st.Uid != uint32(os.Geteuid()) {
		return errors.New("private output directory required")
	}
	return nil
}

func checkPrivateDirectory(path string) error {
	fd, err := parentFD(filepath.Join(path, "probe"))
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&0777 != 0700 || st.Uid != uint32(os.Geteuid()) {
		return errors.New("private directory required")
	}
	return nil
}
