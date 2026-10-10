package identity

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// LeafDirectory pins a validated TLS-hook input directory. Root never follows a
// directory component or reads through an ancestor replaceable by freerad.
type LeafDirectory struct {
	mu       sync.Mutex
	file     *os.File
	ownerUID int
}

// OpenLeafDirectory resolves every component relative to the previous directory
// descriptor. Privileged callers require root-owned, non-group/other-writable
// ancestors; the final private directory belongs to the expected leaf producer.
// Non-root dry-run permits the caller's private ancestry and root-owned sticky
// temporary directories, but still never follows links or reads with root privilege.
func OpenLeafDirectory(path string, ownerUID int) (*LeafDirectory, error) {
	if ownerUID < 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsAny(path, "\x00\r\n") {
		return nil, errors.New("invalid verified leaf directory")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("verified leaf directory unavailable")
	}
	fail := func() (*LeafDirectory, error) {
		_ = unix.Close(fd)
		return nil, errors.New("unsafe verified leaf directory ancestry or ownership")
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || !safeLeafAncestor(st, os.Geteuid()) {
		return fail()
	}
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, component := range components {
		next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return fail()
		}
		_ = unix.Close(fd)
		fd = next
		if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Nlink == 0 {
			return fail()
		}
		if i == len(components)-1 {
			if int(st.Uid) != ownerUID || st.Mode&07777 != 0700 {
				return fail()
			}
		} else if !safeLeafAncestor(st, os.Geteuid()) {
			return fail()
		}
	}
	return &LeafDirectory{file: os.NewFile(uintptr(fd), "verified-leaf-directory"), ownerUID: ownerUID}, nil
}
func safeLeafAncestor(st unix.Stat_t, processUID int) bool {
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Nlink == 0 {
		return false
	}
	if processUID == 0 {
		return st.Uid == 0 && st.Mode&0022 == 0
	}
	if (st.Uid == 0 || int(st.Uid) == processUID) && st.Mode&0022 == 0 {
		return true
	}
	return st.Uid == 0 && st.Mode&unix.S_ISVTX != 0
}

// Read opens a single leaf name relative to the pinned descriptor. No input
// bytes are read before producer ownership, private mode, regular type and
// single-link checks; absolute/nested paths, symlinks and hardlinks are rejected.
func (d *LeafDirectory) Read(name string) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.file == nil || name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, "/\x00\r\n") {
		return nil, errors.New("invalid confined leaf filename")
	}
	fd, err := unix.Openat(int(d.file.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("verified leaf unavailable")
	}
	f := os.NewFile(uintptr(fd), "verified-leaf")
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || int(st.Uid) != d.ownerUID || st.Mode&07777 != 0600 {
		return nil, errors.New("unsafe verified leaf ownership, permissions or links")
	}
	return readLeafPEM(f)
}
func (d *LeafDirectory) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.file == nil {
		return nil
	}
	err := d.file.Close()
	d.file = nil
	return err
}
