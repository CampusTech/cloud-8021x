package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func directory(p string, mode uint32) error {
	fd, err := parent(p+"/.anchor", true)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	return unix.Fchmod(fd, mode)
}
func replaceFile(p string, b []byte, mode uint32, uid, gid int) error {
	fd, err := parent(p, true)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	return replaceAt(fd, p, b, mode, uid, gid)
}
func replaceAt(fd int, p string, b []byte, mode uint32, uid, gid int) error {
	if e := checkParentBinding(fd, p); e != nil {
		return e
	}
	// Exclusive temporary file and rename operate in the retained checked directory.
	name := ".task11-new-" + filepath.Base(p)
	leaf, err := unix.Openat(fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errors.New("preexisting or unsafe candidate publication")
	}
	f := os.NewFile(uintptr(leaf), "candidate")
	if _, err = f.Write(b); err == nil {
		err = unix.Fchown(leaf, uid, gid)
	}
	if err == nil {
		err = unix.Fchmod(leaf, mode)
	}
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err != nil {
		return err
	}
	if ce != nil {
		return ce
	}
	var st unix.Stat_t
	if err = unix.Fstatat(fd, filepath.Base(p), &st, unix.AT_SYMLINK_NOFOLLOW); err == nil && st.Mode&unix.S_IFMT != unix.S_IFREG && st.Mode&unix.S_IFMT != unix.S_IFLNK {
		return errors.New("candidate destination is not a leaf")
	}
	if err != nil && err != unix.ENOENT {
		return err
	}
	if err = unix.Renameat(fd, name, fd, filepath.Base(p)); err != nil {
		return err
	}
	if e := unix.Fsync(fd); e != nil {
		return e
	}
	return checkParentBinding(fd, p)
}
func linkFile(p, target string) error {
	fd, e := parent(p, true)
	if e != nil {
		return e
	}
	defer func() { _ = unix.Close(fd) }()
	if e = unix.Symlinkat(target, fd, filepath.Base(p)); e != nil {
		return e
	}
	return unix.Fsync(fd)
}
func accountIDs(root string) (map[string]int, map[string]int, error) {
	read := func(name string) (map[string]int, error) {
		b, e := readProtected(root+"/etc/"+name, 1<<20)
		if e != nil || len(b) > 1<<20 {
			return nil, errors.New("bounded installed account database unavailable")
		}
		out := map[string]int{}
		for _, line := range strings.Split(string(b), "\n") {
			if line == "" {
				continue
			}
			v := strings.Split(line, ":")
			if len(v) < 3 {
				return nil, errors.New("invalid installed account entry")
			}
			id, e := strconv.Atoi(v[2])
			if e != nil || id < 0 || out[v[0]] != 0 {
				return nil, errors.New("invalid installed account id")
			}
			out[v[0]] = id
		}
		return out, nil
	}
	u, e := read("passwd")
	if e != nil {
		return nil, nil, e
	}
	g, e := read("group")
	return u, g, e
}
func copyPinnedFile(source, target, sha string, limit int64, mode uint32) error {
	// Public baseline hardlinks are copied as independent files. No private
	// input/output or helper gets this exception; bytes remain independently pinned.
	f, e := openPinnedPolicy(source, sha, limit, false, true)
	if e != nil {
		return e
	}
	defer func() { _ = f.Close() }()
	var sourceStat unix.Stat_t
	if unix.Fstat(int(f.Fd()), &sourceStat) != nil || sourceStat.Size != limit || uint32(sourceStat.Mode)&07777 != mode {
		return errors.New("lower source size or mode differs")
	}
	fd, e := parent(target, true)
	if e != nil {
		return e
	}
	defer func() { _ = unix.Close(fd) }()
	dest, e := unix.Openat(fd, filepath.Base(target), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	out := os.NewFile(uintptr(dest), "public-copy")
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(out, h), io.LimitReader(f, limit+1))
	e = copyErr
	if e == nil && (n != limit || hex.EncodeToString(h.Sum(nil)) != sha) {
		e = errors.New("lower bytes changed during copy")
	}
	if e == nil {
		e = unix.Fchmod(dest, mode)
	}
	if e == nil {
		e = out.Sync()
	}
	ce := out.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return unix.Fsync(fd)
}
