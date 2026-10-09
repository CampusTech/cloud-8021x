package main

import (
	"bytes"
	"errors"
	"os"
	"runtime"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	seed "github.com/CampusTech/cloud-8021x/tests/runtime/task11-assembly-seed/contract"
	"golang.org/x/sys/unix"
)

func loadInputs(want string) (prepared, error) {
	var empty prepared
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || !seed.IsSHA(want) {
		return empty, errors.New("linux guest root and independent plan pin required")
	}
	marker, err := readFixed("/etc/cloud8021x-task11-fixture", 0644, 64)
	if err != nil {
		return empty, err
	}
	raw, err := readFixed(planPath, 0600, 16<<10)
	if err != nil || digest(raw) != want {
		return empty, errors.New("protected migration plan pin differs")
	}
	var p plan
	if domain.DecodeJSONStrict(raw, &p) != nil {
		return empty, errors.New("strict migration plan required")
	}
	id, err := readFixed("/etc/machine-id", 0, 64)
	if err != nil {
		return empty, err
	}
	hostname, err := os.Hostname()
	if err != nil {
		return empty, errors.New("hostname unavailable")
	}
	comm, err := os.ReadFile("/proc/1/comm")
	if err != nil || len(comm) > 64 {
		return empty, errors.New("systemd PID1 unavailable")
	}
	exe, err := os.Readlink("/proc/1/exe")
	if err != nil || (exe != "/usr/lib/systemd/systemd" && exe != "/lib/systemd/systemd") {
		return empty, errors.New("systemd PID1 executable differs")
	}
	if err = validateIdentity(identity{os.Geteuid(), string(marker), hostname, string(id), string(comm)}, p.MachineID); err != nil {
		return empty, err
	}
	cfg, err := readFixed(sourceConfig, 0640, 1<<20)
	if err != nil {
		return empty, err
	}
	installed, err := readFixed(installedConfig, 0640, 1<<20)
	if err != nil || !bytes.Equal(cfg, installed) {
		return empty, errors.New("installed source configuration differs")
	}
	input, err := readFixed(seed.OriginalRoot+"/assembly-input.json", 0600, 1<<20)
	if err != nil {
		return empty, err
	}
	api, err := readFixed(seed.OriginalRoot+"/api/seed.json", 0600, 8<<20)
	if err != nil {
		return empty, err
	}
	dsn, err := readFixed(migrationDSN, 0600, 8192)
	if err != nil {
		return empty, err
	}
	ca, err := readFixed(caPath, 0644, 1<<20)
	if err != nil {
		return empty, err
	}
	return validateMaterial(p, input, cfg, api, dsn, ca)
}
func acquireLock() (func(), error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("root directory unavailable")
	}
	for _, part := range strings.Split(strings.TrimPrefix(seed.ControlRoot, "/"), "/") {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if e != nil {
			return nil, errors.New("private lock ancestry unavailable")
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&0022 != 0 {
			_ = unix.Close(fd)
			return nil, errors.New("private lock ancestry refused")
		}
	}
	defer func() { _ = unix.Close(fd) }()
	lock, err := unix.Openat(fd, "blue-migration.lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, errors.New("blue migration lock unavailable")
	}
	var st unix.Stat_t
	if unix.Fstat(lock, &st) != nil || st.Uid != 0 || st.Nlink != 1 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 {
		_ = unix.Close(lock)
		return nil, errors.New("blue migration lock refused")
	}
	if unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB) != nil {
		_ = unix.Close(lock)
		return nil, errors.New("another blue migration is active")
	}
	return func() { _ = unix.Flock(lock, unix.LOCK_UN); _ = unix.Close(lock) }, nil
}
