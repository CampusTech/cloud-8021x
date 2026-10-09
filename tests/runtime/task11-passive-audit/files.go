package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-passive-audit/contract"
	"golang.org/x/sys/unix"
)

type fileRule struct {
	path     string
	uid, gid int
	mode     uint32
	max      int64
}

func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// readAt walks each ancestor without following symlinks. The production anchor
// is always /. The alternative anchor is used only by local filesystem tests.
func readAt(anchor string, r fileRule) ([]byte, contract.File, error) {
	var out contract.File
	if r.max <= 0 {
		return nil, out, errors.New("protected bound invalid")
	}
	fd, leaf, e := parentFD(anchor, r.path, r.uid)
	if e != nil {
		return nil, out, errors.New("protected ancestor unavailable")
	}
	defer func() { _ = unix.Close(fd) }()
	n, e := unix.Openat(fd, leaf, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, out, e
	}
	f := os.NewFile(uintptr(n), "protected-input")
	defer func() { _ = f.Close() }()
	var before unix.Stat_t
	if e = unix.Fstat(n, &before); e != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || int(before.Uid) != r.uid || int(before.Gid) != r.gid || uint32(before.Mode&07777) != r.mode || before.Size < 0 || before.Size > r.max {
		return nil, out, errors.New("protected file metadata differs")
	}
	first, e := f.Stat()
	if e != nil {
		return nil, out, e
	}
	raw, e := io.ReadAll(io.LimitReader(f, r.max+1))
	if e != nil || int64(len(raw)) != before.Size {
		clear(raw)
		return nil, out, errors.New("protected file length differs")
	}
	var after, named unix.Stat_t
	last, e := f.Stat()
	if e != nil || unix.Fstat(n, &after) != nil || unix.Fstatat(fd, leaf, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameStat(before, after) || !sameStat(after, named) || !first.ModTime().Equal(last.ModTime()) {
		clear(raw)
		return nil, out, errors.New("protected file changed during read")
	}
	out = contract.File{SHA256: digest(raw), UID: uint32(before.Uid), GID: uint32(before.Gid), Mode: uint32(before.Mode & 07777), Bytes: before.Size, Device: uint64(before.Dev), Inode: uint64(before.Ino)}
	return raw, out, nil
}
func readProtected(r fileRule) ([]byte, contract.File, error) { return readAt("/", r) }
func absence(path string) error {
	fd, leaf, e := parentFD("/", path, 0)
	if e != nil {
		return errors.New("absence parent unavailable")
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if e = unix.Fstatat(fd, leaf, &st, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(e, unix.ENOENT) {
		return errors.New("activation artifact present or uncertain")
	}
	return nil
}
func parentFD(anchor, path string, owner int) (int, string, error) {
	rel, e := filepath.Rel(anchor, path)
	if e != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return -1, "", errors.New("protected path invalid")
	}
	fd, e := unix.Open(anchor, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, "", e
	}
	parts := strings.Split(rel, string(filepath.Separator))
	for _, part := range parts[:len(parts)-1] {
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if err != nil {
			return -1, "", err
		}
		fd = next
		var st unix.Stat_t
		if err = unix.Fstat(fd, &st); err != nil || st.Mode&0022 != 0 || (int(st.Uid) != 0 && int(st.Uid) != owner) {
			_ = unix.Close(fd)
			return -1, "", errors.New("unsafe protected ancestor")
		}
	}
	return fd, parts[len(parts)-1], nil
}

func sameStat(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Uid == b.Uid && a.Gid == b.Gid && a.Size == b.Size
}

func protectedMask(path string) error {
	fd, leaf, e := parentFD("/", path, 0)
	if e != nil {
		return e
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if unix.Fstatat(fd, leaf, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFLNK || st.Uid != 0 || st.Gid != 0 || st.Nlink != 1 {
		return errors.New("worker mask is not protected root symlink")
	}
	target := make([]byte, 128)
	n, e := unix.Readlinkat(fd, leaf, target)
	if e != nil || string(target[:n]) != "/dev/null" {
		return errors.New("worker mask target differs")
	}
	return nil
}
