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

const producerNASBacking = "/var/lib/cloud8021x-task11/aux/nas/var/lib/cloud8021x-task11-nas"

func producerDirectory(path string, uid int) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || uid < 0 {
		return -1, errors.New("fixed protected directory required")
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, e
	}
	for _, name := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		next, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if err != nil {
			return -1, errors.New("protected parent unavailable")
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || (int(st.Uid) != uid && st.Uid != 0) || (st.Mode&0022 != 0 && (st.Uid != 0 || st.Mode&unix.S_ISVTX == 0)) {
			_ = unix.Close(fd)
			return -1, errors.New("unsafe protected ancestor")
		}
	}
	return fd, nil
}
func producerRead(path string, uid, limit int, mode uint32) ([]byte, error) {
	parent, e := producerDirectory(filepath.Dir(path), uid)
	if e != nil {
		return nil, e
	}
	defer func() { _ = unix.Close(parent) }()
	fd, e := unix.Openat(parent, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, errors.New("fixed protected file unavailable")
	}
	f := os.NewFile(uintptr(fd), "producer-private-input")
	defer func() { _ = f.Close() }()
	valid := func(st unix.Stat_t) bool {
		return int(st.Uid) == uid && st.Mode&unix.S_IFMT == unix.S_IFREG && uint32(st.Mode)&07777 == mode && st.Nlink == 1 && st.Size > 0 && st.Size <= int64(limit)
	}
	var before, after, pathNow unix.Stat_t
	if unix.Fstat(fd, &before) != nil || !valid(before) {
		return nil, errors.New("protected input descriptor differs")
	}
	raw, e := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	current, err := producerDirectory(filepath.Dir(path), uid)
	if err != nil {
		clear(raw)
		return nil, err
	}
	defer func() { _ = unix.Close(current) }()
	var oldParent, newParent unix.Stat_t
	if e != nil || unix.Fstat(fd, &after) != nil || !valid(after) || outerIdentity(before) != outerIdentity(after) || before.Size != after.Size || int64(len(raw)) != after.Size || unix.Fstatat(current, filepath.Base(path), &pathNow, unix.AT_SYMLINK_NOFOLLOW) != nil || outerIdentity(pathNow) != outerIdentity(after) || unix.Fstat(parent, &oldParent) != nil || unix.Fstat(current, &newParent) != nil || outerIdentity(oldParent) != outerIdentity(newParent) {
		clear(raw)
		return nil, errors.New("protected input changed or incomplete")
	}
	return raw, nil
}
func producerBinarySHA(path string) (string, error) {
	parent, e := producerDirectory(filepath.Dir(path), 0)
	if e != nil {
		return "", e
	}
	defer func() { _ = unix.Close(parent) }()
	fd, e := unix.Openat(parent, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return "", errors.New("fixed public executable unavailable")
	}
	f := os.NewFile(uintptr(fd), "fixed-executable")
	defer func() { _ = f.Close() }()
	var a, b, p unix.Stat_t
	if unix.Fstat(fd, &a) != nil || a.Uid != 0 || a.Mode&unix.S_IFMT != unix.S_IFREG || a.Mode&07777 != 0755 || a.Nlink != 1 || a.Size < 64 || a.Size > 256<<20 {
		return "", errors.New("fixed executable unsafe")
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, (256<<20)+1))
	if e != nil || n != a.Size || unix.Fstat(fd, &b) != nil || outerIdentity(a) != outerIdentity(b) || a.Size != b.Size || unix.Fstatat(parent, filepath.Base(path), &p, unix.AT_SYMLINK_NOFOLLOW) != nil || outerIdentity(p) != outerIdentity(a) {
		return "", errors.New("fixed executable changed")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func producerWriteAt(fd, uid int, name string, raw []byte) error {
	if name == "" || filepath.Base(name) != name || len(raw) == 0 || len(raw) > 64<<10 {
		return errors.New("closed bounded exclusive input required")
	}
	child, e := unix.Openat(fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return errors.New("existing or uncertain input refuses replacement")
	}
	f := os.NewFile(uintptr(child), "exclusive-private-publication")
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if unix.Fstat(child, &st) != nil || !privateRecordStat(st, uid, 64<<10) {
		return errors.New("new private descriptor unsafe")
	}
	n, e := f.Write(raw)
	if e != nil || n != len(raw) || f.Sync() != nil || unix.Fsync(fd) != nil {
		return errors.New("partial irreversible publication retained")
	}
	return nil
}
func producerNewDirectory(parent int, name string, uid int) (int, error) {
	if filepath.Base(name) != name || name == "" || unix.Mkdirat(parent, name, 0700) != nil || unix.Fsync(parent) != nil {
		return -1, errors.New("existing or partial publication refuses retry")
	}
	fd, e := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, e
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || int(st.Uid) != uid || st.Mode&07777 != 0700 {
		_ = unix.Close(fd)
		return -1, errors.New("new private directory differs")
	}
	return fd, nil
}

// Only CLI supplies fixed control and NAS backing constants. Parameterization
// here permits actual no-follow/exclusive temporary-directory regression tests.
func publishNASDirectories(controlPath, nasPath string, uid int, b preparedNAS, identity []byte) error {
	if e := validatePreparedNAS(b); e != nil {
		return e
	}
	if len(identity) == 0 || len(identity) > 64<<10 {
		return errors.New("bounded input identity required")
	}
	control, e := protectedDirectoryAt(controlPath, uid)
	if e != nil {
		return e
	}
	defer func() { _ = unix.Close(control) }()
	nasParent, e := producerDirectory(filepath.Dir(nasPath), uid)
	if e != nil {
		return e
	}
	defer func() { _ = unix.Close(nasParent) }()
	// Claim identity, not readiness. A failed or uncertain publication has no retry.
	if e = producerWriteAt(control, uid, "scenario-preparation.json", identity); e != nil {
		return e
	}
	material, e := producerNewDirectory(nasParent, filepath.Base(nasPath), uid)
	if e != nil {
		return e
	}
	defer func() { _ = unix.Close(material) }()
	scenarios, e := producerNewDirectory(control, "scenarios", uid)
	if e != nil {
		return e
	}
	defer func() { _ = unix.Close(scenarios) }()
	plans, e := producerNewDirectory(scenarios, "plans", uid)
	if e != nil {
		return e
	}
	defer func() { _ = unix.Close(plans) }()
	return publishPreparedNAS(b, func(kind, name string, raw []byte) error {
		fd := plans
		if kind == "materials" {
			fd = material
		} else if kind != "plans" {
			return errors.New("unknown fixed publication kind")
		}
		// Verify both pathname roots still identify the held private directory FDs.
		current, e := protectedDirectoryAt(nasPath, uid)
		if e != nil {
			return e
		}
		defer func() { _ = unix.Close(current) }()
		currentPlans, e := protectedDirectoryAt(controlPath+"/scenarios/plans", uid)
		if e != nil {
			return e
		}
		defer func() { _ = unix.Close(currentPlans) }()
		var a, z, c, d unix.Stat_t
		if unix.Fstat(material, &a) != nil || unix.Fstat(current, &z) != nil || outerIdentity(a) != outerIdentity(z) || unix.Fstat(plans, &c) != nil || unix.Fstat(currentPlans, &d) != nil || outerIdentity(c) != outerIdentity(d) {
			return errors.New("private publication backing replaced")
		}
		return producerWriteAt(fd, uid, name, raw)
	})
}
