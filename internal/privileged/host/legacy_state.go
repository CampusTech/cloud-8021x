package host

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/CampusTech/cloud-8021x/internal/migration"
	"golang.org/x/sys/unix"
)

// All paths are deployed legacy constants. No caller-selected privileged read.
var legacyStatePaths = map[string]string{
	"vlan_sources": "/etc/freeradius/3.0/vlan-name-sources.json",
	"policy":       "/etc/freeradius/3.0/device-policy-cache.json",
	"certificates": "/var/lib/cloud-8021x/certificate-state.json",
	"readiness":    "/var/lib/cloud-8021x/certificate-readiness.json",
	"devices":      "/etc/freeradius/3.0/fleet-device-cache.json",
	"unifi":        "/etc/freeradius/3.0/unifi-ap-cache.json",
	"meraki":       "/etc/freeradius/3.0/meraki-ap-cache.json",
	"vlans":        "/etc/freeradius/3.0/vlan-name-cache.json",
	"discovery":    "/var/lib/radius-sources/state.json",
	"usage":        "/var/lib/radius-usage/checkpoint.json",
}

func readLegacyStateComponent(key string, uid int) (*migration.LegacyFile, error) {
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
	return &migration.LegacyFile{Data: data, ModifiedAt: json.Number(strconv.FormatInt(info.ModTime().Unix(), 10) + "." + fmt.Sprintf("%09d", info.ModTime().Nanosecond()))}, nil
}

// CaptureLegacyState is called only after local physical writers are fenced and
// before native replacement. It persists one validated immutable full document.
// SQL comes from the fixed protected Go snapshot; missing/unavailable SQL is not empty.
func CaptureLegacyState(id, node string, class []byte) ([]byte, error) {
	if os.Geteuid() != 0 || len(class) < 32 {
		return nil, errors.New("root legacy Class binding required")
	}
	dir, e := writerReceiptDirectory(id)
	if e != nil {
		return nil, e
	}
	if saved, e := readPrivateCache(filepath.Join(dir, "bundle.json"), 96<<20); e == nil {
		b, e := migration.DecodeBundle(saved)
		if e != nil || b.Node != node || b.ClassKeySHA256 != digestBytes(class) {
			return nil, errors.New("captured bundle binding mismatch")
		}
		return saved, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	uid, _, e := identity("freerad")
	if e != nil {
		return nil, e
	}
	components := map[string]*migration.LegacyFile{}
	for key := range legacyStatePaths {
		c, e := readLegacyStateComponent(key, uid)
		if e != nil {
			return nil, e
		}
		components[key] = c
	}
	if components["policy"] == nil {
		return nil, errors.New("original policy and explicit legacy SQL export/absence evidence required")
	}
	b := migration.Bundle{Version: 1, Node: node, ClassKeySHA256: digestBytes(class), Policy: components["policy"].Data, VLANSources: components["vlan_sources"], UniFi: components["unifi"], Meraki: components["meraki"]}
	sql, e := readLegacySQLCapture(id, node)
	if e != nil {
		return nil, e
	}
	b.SQL = sql.SQL
	for key, target := range map[string]*json.RawMessage{"certificates": &b.Certificates, "readiness": &b.Readiness, "devices": &b.Devices, "vlans": &b.VLANs, "discovery": &b.Discovery, "usage": &b.Usage} {
		if c := components[key]; c != nil {
			*target = bytes.Clone(c.Data)
		}
	}
	b.UsageAbsent = components["usage"] == nil
	guard, e := snapshotState(File{Path: legacyDowngradeGuard})
	if e != nil {
		return nil, e
	}
	b.FingerprintEnforced = guard.Exists
	legacy, e := legacyClassSnapshot()
	if e != nil || !legacy.Exists || !bytes.Equal(legacy.Data, class) {
		return nil, errors.New("original shared Class key unavailable or differs")
	}
	data, e := json.Marshal(b)
	if e != nil {
		return nil, e
	}
	if _, e = migration.DecodeBundle(data); e != nil {
		return nil, e
	}
	if e = privateWrite(filepath.Join(dir, "bundle.json"), data, 0600); e != nil {
		return nil, e
	}
	if e = syncWriterDirectory(dir); e != nil {
		return nil, e
	}
	return data, nil
}
func ReadCapturedLegacyState(id, node string, class []byte) ([]byte, error) {
	dir, e := writerReceiptDirectory(id)
	if e != nil {
		return nil, e
	}
	data, e := readPrivateCache(filepath.Join(dir, "bundle.json"), 96<<20)
	if e != nil {
		return nil, e
	}
	b, e := migration.DecodeBundle(data)
	if e != nil || b.Node != node || b.ClassKeySHA256 != digestBytes(class) {
		return nil, errors.New("captured legacy state binding mismatch")
	}
	return data, nil
}

// CheckLegacyCaptureClass refuses a missing legacy key; only positively proven
// fresh hosts can use the separate unavailable seed path.
func CheckLegacyCaptureClass(candidate []byte) error {
	old, e := legacyClassSnapshot()
	if e != nil {
		return e
	}
	if !old.Exists || len(candidate) < 32 || !bytes.Equal(old.Data, candidate) {
		return errors.New("exact original legacy Class key required")
	}
	return nil
}
