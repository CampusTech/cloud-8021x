package host

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// Only these fixed original authorization inputs enter parallel source capture.
// They remain read-only and never enter the privileged output allowlist.
var legacyStatePaths = map[string]string{
	"policy":       "/etc/freeradius/3.0/device-policy-cache.json",
	"certificates": "/var/lib/cloud-8021x/certificate-state.json",
}

type legacyStateComponent struct {
	ModifiedAt json.Number
	Data       json.RawMessage
}

func readLegacyStateComponent(key string, uid int) (*legacyStateComponent, error) {
	path, ok := legacyStatePaths[key]
	if !ok {
		return nil, errors.New("unknown legacy component")
	}
	parent, e := stateParentDescriptor(path, uid)
	if errors.Is(e, unix.ENOENT) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	defer func() { _ = unix.Close(parent) }()
	fd, e := unix.Openat(parent, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(e, unix.ENOENT) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "legacy-state")
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0022 != 0 || st.Nlink != 1 || (st.Uid != 0 && int(st.Uid) != uid) {
		return nil, errors.New("unsafe legacy state")
	}
	data, e := io.ReadAll(io.LimitReader(f, 64<<20+1))
	if e != nil || len(data) > 64<<20 {
		return nil, errors.New("legacy state exceeds bound")
	}
	info, e := f.Stat()
	if e != nil {
		return nil, e
	}
	return &legacyStateComponent{Data: data, ModifiedAt: json.Number(strconv.FormatInt(info.ModTime().Unix(), 10) + "." + fmt.Sprintf("%09d", info.ModTime().Nanosecond()))}, nil
}
