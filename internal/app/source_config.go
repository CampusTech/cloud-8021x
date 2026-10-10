package app

import (
	"errors"
	"os"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"golang.org/x/sys/unix"
)

// Source apply reopens the fixed protected configuration through root-owned,
// unwritable directory descriptors. Neither ancestor symlinks nor a replaced
// daemon-writable config path can select root resources or credentials.
func readProtectedSourceConfig() (config.Config, error) {
	return readFixedProtectedConfig(privilegedConfigFile)
}
func readFixedProtectedConfig(path string) (config.Config, error) {
	if path != privilegedConfigFile && path != "/var/cache/cloud-8021x/artifacts/config.yaml" {
		return config.Config{}, errors.New("fixed root config required")
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return config.Config{}, errors.New("protected source configuration unavailable")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, part := range parts[:len(parts)-1] {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if e != nil {
			return config.Config{}, errors.New("unsafe source configuration ancestry")
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&0022 != 0 {
			_ = unix.Close(fd)
			return config.Config{}, errors.New("source configuration ancestry must be root-owned and non-writable")
		}
	}
	defer func() { _ = unix.Close(fd) }()
	leaf, e := unix.Openat(fd, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return config.Config{}, errors.New("protected source configuration unavailable")
	}
	f := os.NewFile(uintptr(leaf), "protected-source-config")
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if unix.Fstat(leaf, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Nlink != 1 || st.Mode&0022 != 0 {
		return config.Config{}, errors.New("source configuration must be a root-owned non-writable regular file")
	}
	return config.Decode(f)
}
