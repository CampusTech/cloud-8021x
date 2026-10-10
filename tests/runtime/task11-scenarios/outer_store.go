package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
)

type outerFileIdentity struct{ device, inode uint64 }
type outerStore struct {
	fd          int
	uid         int
	path        string
	root        outerFileIdentity
	directories map[string]outerFileIdentity
}

var outerRecordPattern = regexp.MustCompile(`^task11-[0-9a-f]{32}-([1-9]|1[0-9]|2[0-4])\.json$`)

func outerIdentity(st unix.Stat_t) outerFileIdentity {
	return outerFileIdentity{uint64(st.Dev), st.Ino}
}
func protectedDirectoryAt(path string, uid int) (int, error) {
	if uid < 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, errors.New("canonical protected directory required")
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, e
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(fd)
		if err != nil {
			return -1, errors.New("protected directory unavailable")
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || (int(st.Uid) != 0 && int(st.Uid) != uid) || (st.Mode&0022 != 0 && (st.Uid != 0 || st.Mode&unix.S_ISVTX == 0)) {
			_ = unix.Close(fd)
			return -1, errors.New("unsafe protected ancestor")
		}
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || int(st.Uid) != uid || st.Mode&07777 != 0700 {
		_ = unix.Close(fd)
		return -1, errors.New("protected directory identity differs")
	}
	return fd, nil
}
func openOuterStore(path string, uid int) (*outerStore, error) {
	fd, e := protectedDirectoryAt(path, uid)
	if e != nil {
		return nil, e
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		_ = unix.Close(fd)
		return nil, errors.New("protected root unavailable")
	}
	return &outerStore{fd: fd, uid: uid, path: path, root: outerIdentity(st), directories: map[string]outerFileIdentity{}}, nil
}
func (s *outerStore) close() {
	if s != nil && s.fd >= 0 {
		_ = unix.Close(s.fd)
		s.fd = -1
	}
}
func (s *outerStore) check() error {
	if s == nil || s.fd < 0 {
		return errors.New("protected store closed")
	}
	current, e := protectedDirectoryAt(s.path, s.uid)
	if e != nil {
		return e
	}
	defer func() { _ = unix.Close(current) }()
	var st unix.Stat_t
	if unix.Fstat(current, &st) != nil || outerIdentity(st) != s.root {
		return errors.New("protected store replaced")
	}
	return nil
}
func outerCase(name string) bool {
	switch name {
	case "native-accounting", "ongoing-interim", "ongoing-stop", "duplicate-pair", "ha-primary", "postgres-outage", "business-outage", "ca-ec-continuity", "ca-rsa-continuity":
		return true
	}
	return false
}
func outerName(dir, name string) bool {
	switch dir {
	case "requests", "results", "failures", "claims", "ca-selections":
		return outerRecordPattern.MatchString(name)
	case "attempts", "plans":
		return strings.HasSuffix(name, ".json") && outerCase(strings.TrimSuffix(name, ".json"))
	}
	return false
}
func (s *outerStore) directory(dir, name string, create bool) (int, error) {
	if !outerName(dir, name) || s.check() != nil {
		return -1, errors.New("closed protected record binding required")
	}
	if create {
		if e := unix.Mkdirat(s.fd, dir, 0700); e != nil && e != unix.EEXIST {
			return -1, e
		}
		if unix.Fsync(s.fd) != nil {
			return -1, errors.New("protected directory not durable")
		}
	}
	fd, e := unix.Openat(s.fd, dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, e
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || int(st.Uid) != s.uid || st.Mode&07777 != 0700 {
		_ = unix.Close(fd)
		return -1, errors.New("private record directory differs")
	}
	identity := outerIdentity(st)
	if old, ok := s.directories[dir]; ok && old != identity {
		_ = unix.Close(fd)
		return -1, errors.New("private record directory replaced")
	}
	s.directories[dir] = identity
	return fd, nil
}
func privateRecordStat(st unix.Stat_t, uid, max int) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFREG && int(st.Uid) == uid && st.Mode&07777 == 0600 && st.Nlink == 1 && st.Size >= 0 && st.Size <= int64(max)
}
func (s *outerStore) read(dir, name string, max int) ([]byte, error) {
	if max < 1 || max > 8<<20 {
		return nil, errors.New("bounded record limit required")
	}
	fd, e := s.directory(dir, name, false)
	if e != nil {
		return nil, e
	}
	defer func() { _ = unix.Close(fd) }()
	child, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	file := os.NewFile(uintptr(child), name)
	defer func() { _ = file.Close() }()
	var before, after unix.Stat_t
	if unix.Fstat(child, &before) != nil || !privateRecordStat(before, s.uid, max) {
		return nil, errors.New("private record descriptor differs")
	}
	raw, e := io.ReadAll(io.LimitReader(file, int64(max)+1))
	if e != nil || unix.Fstat(child, &after) != nil || !privateRecordStat(after, s.uid, max) || outerIdentity(before) != outerIdentity(after) || before.Size != after.Size || int64(len(raw)) != after.Size || s.check() != nil {
		clear(raw)
		return nil, errors.New("private record changed or incomplete")
	}
	return raw, nil
}
func (s *outerStore) create(dir, name string, raw []byte) error {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return errors.New("bounded exclusive record required")
	}
	fd, e := s.directory(dir, name, true)
	if e != nil {
		return e
	}
	defer func() { _ = unix.Close(fd) }()
	child, e := unix.Openat(fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	file := os.NewFile(uintptr(child), name)
	defer func() { _ = file.Close() }()
	var st unix.Stat_t
	if unix.Fstat(child, &st) != nil || !privateRecordStat(st, s.uid, 64<<10) {
		return errors.New("new private record differs")
	}
	n, e := file.Write(raw)
	// A partial irreversible record is intentionally retained and blocks retries.
	if e != nil || n != len(raw) || file.Sync() != nil || unix.Fsync(fd) != nil || s.check() != nil {
		return errors.New("exclusive private record incomplete or not durable")
	}
	return nil
}

func (s *outerStore) checkRecordDirectory(dir, knownName string) error {
	fd, e := s.directory(dir, knownName, false)
	if errors.Is(e, unix.ENOENT) {
		return nil
	}
	if e != nil {
		return e
	}
	file := os.NewFile(uintptr(fd), "scenario-record-directory")
	defer func() { _ = file.Close() }()
	entries, e := file.ReadDir(257)
	if e != nil && e != io.EOF {
		return errors.New("bounded protected history listing failed")
	}
	if len(entries) > 256 {
		return errors.New("protected history directory bound exceeded")
	}
	for _, entry := range entries {
		if !outerRecordPattern.MatchString(entry.Name()) {
			return errors.New("unknown protected history filename")
		}
		var st unix.Stat_t
		if unix.Fstatat(fd, entry.Name(), &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !privateRecordStat(st, s.uid, 8<<20) {
			return errors.New("unsafe protected history file")
		}
	}
	return s.check()
}
