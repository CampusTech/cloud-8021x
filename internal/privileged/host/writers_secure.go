package host

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/sys/unix"
)

const legacyVLANModule = "/etc/freeradius/3.0/mods-config/python3/vlan_names.py"
const vlanTail = "if __name__ == '__main__':\n    sys.exit(main())\n"

var inertHelper = []byte("#!/bin/sh\n# cloud-8021x legacy writer fenced\nexit 0\n")
var inertCron = []byte("# cloud-8021x legacy writer fenced\n")
var vlanLineage = []string{"/etc/freeradius", "/etc/freeradius/3.0", "/etc/freeradius/3.0/mods-config", "/etc/freeradius/3.0/mods-config/python3"}

type writerDirectory struct {
	Path          string
	UID, GID      int
	Mode          uint32
	Device, Inode uint64
}
type writerProcess struct {
	PID, Parent int
	Start       uint64
	Args        string
}
type writerPID struct {
	PID   int
	Start uint64
}

func legacyWriterPaths() []string {
	paths := append(append(append([]string{}, legacyWriterCrons...), legacyWriterHelpers...), legacyVLANModule)
	return append(paths, writerUnitPaths(legacyWriterUnits)...)
}
func inertVLANModule(data []byte) ([]byte, error) {
	if !bytes.HasSuffix(data, []byte(vlanTail)) || bytes.Count(data, []byte("if __name__")) != 1 {
		return nil, errors.New("unrecognized VLAN library CLI tail")
	}
	return append(bytes.Clone(data[:len(data)-len(vlanTail)]), []byte("if __name__ == '__main__':\n    sys.exit(0)  # cloud-8021x legacy writer fenced\n")...), nil
}

// Receipts are our own canonical JSON, never operator-authored instructions.
// Canonical byte equality also rejects duplicate and case-aliased JSON fields.
// Validate the ENTIRE document before any restoration side effect.
func decodeWriterReceipt(data []byte, id string) (writerReceipt, error) {
	var r writerReceipt
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if len(data) > 16<<20 || d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF {
		return r, errors.New("invalid writer receipt schema")
	}
	canonical, e := json.Marshal(r)
	if e != nil || !bytes.Equal(canonical, data) || r.Version != 1 || r.Transition != id || (r.Node != "radius-primary" && r.Node != "radius-secondary") || len(r.ConfigSHA256) != 64 || strings.Trim(r.ConfigSHA256, "0123456789abcdef") != "" {
		return r, errors.New("invalid writer receipt binding")
	}
	seen := map[string]bool{}
	for _, s := range r.Files {
		if !slices.Contains(legacyWriterPaths(), s.Path) || seen[s.Path] || s.ReplacementUID != 0 || s.GID < 0 || s.GID > 1<<31-1 || s.UID < 0 || s.Mode > 0777 || s.Mode&0022 != 0 || len(s.Data) > 4<<20 {
			return r, errors.New("invalid writer receipt file")
		}
		if !s.Exists && (s.UID != 0 || s.GID != 0 || s.Mode != 0 || len(s.Data) != 0) {
			return r, errors.New("invalid absent writer file")
		}
		if s.UID != 0 && (s.Path != legacyVLANModule || s.UID != r.NativeUID) {
			return r, errors.New("invalid writer receipt owner")
		}
		if s.Path == legacyVLANModule && s.Exists {
			if len(r.Directories) != len(vlanLineage) {
				return r, errors.New("incomplete VLAN ancestry receipt")
			}
			if _, e := inertVLANModule(s.Data); e != nil {
				return r, e
			}
		}
		seen[s.Path] = true
	}
	for _, p := range r.Masks {
		if !slices.Contains(writerUnitPaths(legacyWriterUnits), p) || seen[p] {
			return r, errors.New("invalid prior writer mask")
		}
		seen[p] = true
	}
	if len(seen) != len(legacyWriterPaths()) {
		return r, errors.New("incomplete writer receipt")
	}
	if r.NativeUID < 0 || r.NativeUID > 1<<31-1 || len(r.Directories) > len(vlanLineage) || (len(r.Directories) > 0 && r.NativeUID < 1) {
		return r, errors.New("invalid writer ancestry receipt")
	}
	for i, d := range r.Directories {
		if d.Path != vlanLineage[i] || (d.UID != 0 && d.UID != r.NativeUID) || d.GID < 0 || d.Mode > 0777 || d.Mode&0022 != 0 || d.Inode == 0 {
			return r, errors.New("invalid writer ancestry")
		}
	}
	pids := map[int]bool{}
	if len(r.Processes) > 100000 {
		return r, errors.New("writer process evidence exceeds bound")
	}
	for _, p := range r.Processes {
		if p.PID <= 0 || p.Start == 0 || pids[p.PID] {
			return r, errors.New("invalid process evidence")
		}
		pids[p.PID] = true
	}
	return r, nil
}

// Pin every ancestor from /. Only this exact legacy module lineage may have
// its original freerad owner. This never changes generic installed-file rules.
func writerParent(path string, nativeUID int) (int, error) {
	if !slices.Contains(legacyWriterLocks, path) && path != legacyVLANModule && !slices.Contains(vlanLineage, path) {
		return -1, errors.New("unapproved writer path")
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, e
	}
	prefix := ""
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/") {
		prefix += "/" + part
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if e != nil {
			return -1, e
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Mode&0022 != 0 || (st.Uid != 0 && (!slices.Contains(vlanLineage, prefix) || nativeUID <= 0 || int(st.Uid) != nativeUID)) {
			_ = unix.Close(fd)
			return -1, errors.New("unsafe legacy writer ancestor")
		}
	}
	return fd, nil
}
func snapshotWriterLineage() ([]writerDirectory, int, error) {
	var out []writerDirectory
	uid, _, err := identity("freerad")
	if err != nil {
		if _, e := os.Lstat("/etc/freeradius"); errors.Is(e, os.ErrNotExist) {
			return out, 0, nil
		}
		return nil, 0, err
	}
	for _, path := range vlanLineage {
		parent, e := writerParent(path, uid)
		if e != nil {
			return nil, 0, e
		}
		fd, e := unix.Openat(parent, filepath.Base(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(parent)
		if errors.Is(e, unix.ENOENT) {
			break
		}
		if e != nil {
			return nil, 0, e
		}
		var st unix.Stat_t
		e = unix.Fstat(fd, &st)
		_ = unix.Close(fd)
		if e != nil || (st.Uid != 0 && int(st.Uid) != uid) || st.Mode&0022 != 0 {
			return nil, 0, errors.New("unsafe fixed writer lineage")
		}
		out = append(out, writerDirectory{path, int(st.Uid), int(st.Gid), uint32(st.Mode) & 0777, uint64(st.Dev), uint64(st.Ino)})
	}
	return out, uid, nil
}

// Durably saved metadata precedes any chown. Top-down protection prevents a
// native owner replacing an ancestor while deeper pinned nodes are protected.
func protectWriterLineage(r writerReceipt, restore bool) error {
	dirs := slices.Clone(r.Directories)
	if restore {
		slices.Reverse(dirs)
	}
	for _, d := range dirs {
		parent, e := writerParent(d.Path, r.NativeUID)
		if e != nil {
			return e
		}
		fd, e := unix.Openat(parent, filepath.Base(d.Path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			_ = unix.Close(parent)
			return e
		}
		var st unix.Stat_t
		e = unix.Fstat(fd, &st)
		if e != nil || uint64(st.Dev) != d.Device || uint64(st.Ino) != d.Inode || (st.Uid != 0 && int(st.Uid) != d.UID) || st.Mode&0022 != 0 {
			_ = unix.Close(fd)
			_ = unix.Close(parent)
			return errors.New("writer lineage identity changed")
		}
		uid, mode := 0, writerDirectoryMode(d, r.NativeUID)
		if restore {
			uid, mode = d.UID, d.Mode
		}
		if e = unix.Fchown(fd, uid, d.GID); e == nil {
			e = unix.Fchmod(fd, mode)
		}
		if e == nil {
			e = unix.Fsync(fd)
		}
		var after unix.Stat_t
		if e == nil && (unix.Fstatat(parent, filepath.Base(d.Path), &after, unix.AT_SYMLINK_NOFOLLOW) != nil || after.Ino != st.Ino || after.Dev != st.Dev || int(after.Uid) != uid) {
			e = errors.New("writer lineage path replaced")
		}
		_ = unix.Close(fd)
		_ = unix.Close(parent)
		if e != nil {
			return e
		}
	}
	return nil
}
func snapshotVLAN(uid int) (SavedFile, error) { return snapshotVLANWithTail(uid, true) }
func snapshotVLANWithTail(uid int, checkTail bool) (SavedFile, error) {
	parent, e := writerParent(legacyVLANModule, uid)
	if errors.Is(e, unix.ENOENT) {
		return SavedFile{File: File{Path: legacyVLANModule}}, nil
	}
	if e != nil {
		return SavedFile{}, e
	}
	defer func() { _ = unix.Close(parent) }()
	fd, e := unix.Openat(parent, filepath.Base(legacyVLANModule), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(e, unix.ENOENT) {
		return SavedFile{File: File{Path: legacyVLANModule}}, nil
	}
	if e != nil {
		return SavedFile{}, e
	}
	f := os.NewFile(uintptr(fd), "legacy-vlan-module")
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Nlink != 1 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0022 != 0 || (st.Uid != 0 && int(st.Uid) != uid) {
		return SavedFile{}, errors.New("unsafe legacy VLAN module")
	}
	data, e := io.ReadAll(io.LimitReader(f, 4<<20+1))
	if e != nil || len(data) > 4<<20 {
		return SavedFile{}, errors.New("legacy VLAN module exceeds bound")
	}
	if _, e = inertVLANModule(data); checkTail && e != nil {
		return SavedFile{}, e
	}
	return SavedFile{File: File{Path: legacyVLANModule, Data: data, UID: int(st.Uid), GID: int(st.Gid), Mode: uint32(st.Mode) & 0777}, Exists: true}, nil
}

func knownWriterArgs(args string) bool {
	scripts := append(append([]string{}, legacyWriterHelpers...), legacyVLANModule, "/etc/freeradius/3.0/mods-config/python3/radius_sources.py", "/usr/local/bin/radius-cert-renew.sh", "/usr/local/sbin/renew-webhook-tls", "radius_usage_service.py", "radius_usage_collector.py")
	tokens := strings.FieldsFunc(args, func(r rune) bool { return r == 0 || unicode.IsSpace(r) || strings.ContainsRune("'\";|&()<>", r) })
	for _, arg := range tokens {
		for _, script := range scripts {
			if arg == script || filepath.Base(arg) == filepath.Base(script) {
				return true
			}
		}
	}
	return false
}
func writerProcessEvidence(processes []writerProcess) []writerPID {
	selected := map[int]bool{}
	for _, p := range processes {
		if knownWriterArgs(p.Args) {
			selected[p.PID] = true
		}
	}
	for changed := true; changed; {
		changed = false
		for _, p := range processes {
			if selected[p.Parent] && !selected[p.PID] {
				selected[p.PID] = true
				changed = true
			}
		}
	}
	var out []writerPID
	for _, p := range processes {
		if selected[p.PID] {
			out = append(out, writerPID{p.PID, p.Start})
		}
	}
	slices.SortFunc(out, func(a, b writerPID) int { return a.PID - b.PID })
	return out
}
func checkWriterProcesses(processes []writerProcess, observed []writerPID) error {
	if len(writerProcessEvidence(processes)) != 0 {
		return errors.New("legacy writer process tree still active")
	}
	for _, p := range processes {
		for _, old := range observed {
			if p.PID == old.PID && p.Start == old.Start {
				return errors.New("observed writer descendant still active")
			}
		}
	}
	return nil
}
func scanWriterProcesses() ([]writerProcess, error) {
	d, e := os.Open("/proc")
	if e != nil {
		return nil, errors.New("process inventory unavailable")
	}
	defer func() { _ = d.Close() }()
	names, e := d.Readdirnames(100001)
	if (e != nil && !errors.Is(e, io.EOF)) || len(names) > 100000 {
		return nil, errors.New("process inventory exceeds bound")
	}
	var out []writerProcess
	for _, name := range names {
		pid, e := strconv.Atoi(name)
		if e != nil {
			continue
		}
		dir := filepath.Join("/proc", name)
		stat, e := os.ReadFile(filepath.Join(dir, "stat"))
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil || len(stat) > 64<<10 {
			return nil, errors.New("process identity unavailable")
		}
		end := bytes.LastIndexByte(stat, ')')
		if end < 1 {
			return nil, errors.New("invalid process identity")
		}
		fields := strings.Fields(string(stat[end+1:]))
		if len(fields) < 20 {
			return nil, errors.New("short process identity")
		}
		parent, e := strconv.Atoi(fields[1])
		if e != nil {
			return nil, e
		}
		start, e := strconv.ParseUint(fields[19], 10, 64)
		if e != nil || start == 0 {
			return nil, errors.New("invalid process start")
		}
		args, e := os.ReadFile(filepath.Join(dir, "cmdline"))
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil || len(args) > 64<<10 {
			return nil, errors.New("process arguments unavailable")
		}
		again, e := os.ReadFile(filepath.Join(dir, "stat"))
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil || !bytes.Equal(stat, again) {
			// CPU counters may change; only the PID/start tuple must remain identical.
			j := bytes.LastIndexByte(again, ')')
			if j < 1 {
				return nil, errors.New("process rescan unavailable")
			}
			f := strings.Fields(string(again[j+1:]))
			if e != nil || len(f) < 20 || f[19] != fields[19] {
				return nil, errors.New("process identity raced")
			}
		}
		out = append(out, writerProcess{pid, parent, start, string(args)})
	}
	return out, nil
}

func writerDirectoryMode(d writerDirectory, nativeUID int) uint32 {
	mode := d.Mode
	if d.UID == nativeUID {
		mode |= 0050
	}
	return mode
}

// Read every recorded live directory binding before restoration writes any file.
func verifyWriterLineage(r writerReceipt) error {
	for _, d := range r.Directories {
		parent, e := writerParent(d.Path, 0)
		if e != nil {
			return e
		}
		fd, e := unix.Openat(parent, filepath.Base(d.Path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(parent)
		if e != nil {
			return e
		}
		var st unix.Stat_t
		e = unix.Fstat(fd, &st)
		_ = unix.Close(fd)
		if e != nil || uint64(st.Dev) != d.Device || uint64(st.Ino) != d.Inode || st.Uid != 0 || int(st.Gid) != d.GID || uint32(st.Mode)&0777 != writerDirectoryMode(d, r.NativeUID) {
			return errors.New("protected writer lineage changed")
		}
	}
	return nil
}
