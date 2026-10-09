//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-passive-audit/contract"
	"golang.org/x/sys/unix"
)

func kernelRead(path string, max int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer func() { _ = f.Close() }()
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max {
		return nil, errors.New("kernel observation exceeds bound")
	}
	return b, nil
}
func identity(r contract.Request) (out contract.Identity, e error) {
	machine, _, e := readProtected(fileRule{path: "/etc/machine-id", uid: 0, gid: 0, mode: 0444, max: 64})
	if e != nil {
		return out, e
	}
	out.MachineID = strings.TrimSpace(string(machine))
	hostname, _, e := readProtected(fileRule{path: "/etc/hostname", uid: 0, gid: 0, mode: 0644, max: 128})
	if e != nil {
		return out, e
	}
	out.Hostname = strings.TrimSpace(string(hostname))
	actualHost, e := os.Hostname()
	if e != nil || actualHost != out.Hostname {
		return out, errors.New("actual hostname differs")
	}
	boot, e := kernelRead("/proc/sys/kernel/random/boot_id", 64)
	if e != nil {
		return out, e
	}
	out.BootID = strings.TrimSpace(string(boot))
	if out.MachineID != r.MachineID || out.Hostname != "task11-"+r.Node || out.BootID != r.BootID {
		return out, errors.New("actual enrolled boot/node identity differs")
	}
	comm, e := kernelRead("/proc/1/comm", 64)
	if e != nil || string(comm) != "systemd\n" {
		return out, errors.New("actual systemd PID1 required")
	}
	exe, e := os.Readlink("/proc/1/exe")
	if e != nil || !slices.Contains([]string{"/usr/lib/systemd/systemd", "/lib/systemd/systemd"}, exe) {
		return out, errors.New("actual PID1 executable differs")
	}
	out.PID1 = "1"
	out.PID1Executable = exe
	stat, e := kernelRead("/proc/1/stat", 4096)
	if e != nil {
		return out, e
	}
	start, _, e := parseStat(stat)
	if e != nil {
		return out, e
	}
	out.PID1Start = strconv.FormatUint(start, 10)
	out.Namespaces = map[string]string{}
	for _, name := range contract.NamespaceNames {
		self, e := os.Readlink("/proc/self/ns/" + name)
		if e != nil {
			return out, e
		}
		init, e := os.Readlink("/proc/1/ns/" + name)
		if e != nil || self != init || self != r.Namespaces[name] {
			return out, errors.New("actual node namespace differs")
		}
		out.Namespaces[name] = self
	}
	return out, nil
}

func units(ctx context.Context) ([]contract.Unit, error) {
	names := append(slices.Clone(contract.Services), contract.Timers...)
	out := []contract.Unit{}
	for _, name := range names {
		args := []string{"show", name, "--no-pager"}
		keys := unitProperties(name)
		for _, k := range keys {
			args = append(args, "--property="+k)
		}
		child, cancel := context.WithTimeout(ctx, 5e9)
		cmd := exec.CommandContext(child, "/usr/bin/systemctl", args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "SYSTEMD_PAGER=cat"}
		b := &boundedBuffer{limit: 32 << 10}
		cmd.Stdout = b
		cmd.Stderr = b
		e := cmd.Run()
		cancel()
		if e != nil {
			return nil, errors.New("actual systemd unit observation failed")
		}
		u, e := parseUnit(b.String(), name)
		if e != nil {
			return nil, e
		}
		out = append(out, u)

	}
	return out, nil
}
func processes() ([]contract.Process, error) {
	dirs, e := os.ReadDir("/proc")
	if e != nil {
		return nil, e
	}
	out := []contract.Process{}
	for _, entry := range dirs {
		pid, e := strconv.Atoi(entry.Name())
		if e != nil || pid <= 0 {
			continue
		}
		if len(out) >= 4096 {
			return nil, errors.New("process snapshot exceeds bound")
		}
		base := "/proc/" + entry.Name()
		stat, e := kernelRead(base+"/stat", 65536)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return nil, e
		}
		start, _, e := parseStat(stat)
		if e != nil {
			return nil, e
		}
		path, e := os.Readlink(base + "/exe")
		if errors.Is(e, os.ErrNotExist) { // Kernel threads have no exe and no userspace command line.
			args, ae := kernelRead(base+"/cmdline", 65536)
			if ae != nil {
				if errors.Is(ae, os.ErrNotExist) {
					continue
				}
				return nil, ae
			}
			if len(args) != 0 {
				return nil, errors.New("userspace process executable disappeared")
			}
			continue
		}
		if e != nil {
			return nil, e
		}
		args, e := kernelRead(base+"/cmdline", 65536)
		if e != nil {
			return nil, e
		}
		name := filepath.Base(strings.TrimSuffix(path, " (deleted)"))
		argv := bytes.Split(args, []byte{0})
		if len(argv) > 0 && filepath.Base(string(argv[0])) == "cloud-8021x" {
			return nil, errors.New("daemon command process present")
		}
		if slices.Contains([]string{"cloud-8021x", "freeradius", "radiusd", "step-ca", "agent", "otel-agent"}, name) {
			return nil, errors.New("mutating product process present")
		}
		f, e := os.Open(base + "/exe")
		if e != nil {
			return nil, errors.New("process executable changed")
		}
		raw, e := io.ReadAll(io.LimitReader(f, (256<<20)+1))
		_ = f.Close()
		if e != nil || len(raw) > 256<<20 {
			return nil, errors.New("process executable exceeds bound")
		}
		hash := digest(raw)
		clear(raw)
		after, e := kernelRead(base+"/stat", 65536)
		if e != nil {
			return nil, errors.New("process identity changed")
		}
		later, _, e := parseStat(after)
		if e != nil || later != start {
			return nil, errors.New("process PID reused")
		}
		out = append(out, contract.Process{PID: pid, Start: start, ExecutableSHA256: hash})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out, nil
}
func sockets() ([]contract.Socket, error) {
	out := []contract.Socket{}
	for _, protocol := range []string{"tcp", "tcp6", "udp", "udp6"} {
		raw, e := kernelRead("/proc/net/"+protocol, 1<<20)
		if e != nil {
			return nil, e
		}
		part, e := parseSockets(raw, protocol)
		if e != nil {
			return nil, e
		}
		out = append(out, part...)
	}
	if len(out) > 4096 {
		return nil, errors.New("aggregate sockets exceed bound")
	}
	return out, nil
}
func collector() (out contract.Mount, e error) {
	raw, e := kernelRead("/proc/self/mountinfo", 1<<20)
	if e != nil {
		return out, e
	}
	count := 0
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) < 10 || f[4] != "/var/lib/cloud8021x/collector" {
			continue
		}
		count++
		dash := slices.Index(f, "-")
		if dash < 6 || len(f) < dash+4 || f[3] != "/" || f[dash+1] != "ext4" || !strings.HasPrefix(f[dash+2], "/dev/loop") || !strings.HasPrefix(f[2], "7:") {
			return out, errors.New("collector mount identity differs")
		}
		out.Device = f[2]
		out.Source = f[dash+2]
		out.Filesystem = f[dash+1]
		out.Options = strings.Split(f[5], ",")
		for _, option := range []string{"rw", "nodev", "nosuid", "noexec"} {
			if !slices.Contains(out.Options, option) {
				return out, errors.New("collector mount isolation differs")
			}
		}
	}
	if count != 1 {
		return out, errors.New("unique actual collector mount required")
	}
	loop := filepath.Base(out.Source)
	if _, e = strconv.ParseUint(strings.TrimPrefix(loop, "loop"), 10, 32); e != nil {
		return out, errors.New("loop device malformed")
	}
	backing, e := kernelRead("/sys/class/block/"+loop+"/loop/backing_file", 4096)
	if e != nil {
		return out, e
	}
	out.BackingFile = "/" + strings.TrimPrefix(strings.TrimSpace(string(backing)), "/")
	if out.BackingFile != "/var/lib/cloud-8021x-bootstrap/collector.ext4" {
		return out, errors.New("collector backing path differs")
	}
	// Read only the immutable filesystem identity header, never hash the mutable
	// mounted journal or write to the image. Protected ancestors are root-owned.
	fd, leaf, e := parentFD("/", out.BackingFile, 0)
	if e != nil {
		return out, e
	}
	defer func() { _ = unix.Close(fd) }()
	var parent unix.Stat_t
	if unix.Fstat(fd, &parent) != nil || parent.Uid != 0 || parent.Gid != 0 || parent.Mode&0022 != 0 {
		return out, errors.New("collector backing parent unsafe")
	}
	image, e := unix.Openat(fd, leaf, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return out, e
	}
	defer func() { _ = unix.Close(image) }()
	var st unix.Stat_t
	if unix.Fstat(image, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Uid != 0 || st.Gid != 0 || st.Nlink != 1 || st.Size != 512<<20 {
		return out, errors.New("collector backing image differs")
	}
	header := make([]byte, 1024)
	n, e := unix.Pread(image, header, 1024)
	if e != nil || n != 1024 || header[56] != 0x53 || header[57] != 0xef {
		return out, errors.New("actual ext4 identity unavailable")
	}
	u := fmtHex(header[104:120])
	out.UUID = fmt.Sprintf("%s-%s-%s-%s-%s", u[:8], u[8:12], u[12:16], u[16:20], u[20:])
	out.Bytes = uint64(st.Size)
	out.Image = contract.File{UID: st.Uid, GID: st.Gid, Mode: uint32(st.Mode & 07777), Bytes: st.Size, Device: uint64(st.Dev), Inode: uint64(st.Ino)}
	var fs unix.Statfs_t
	if unix.Statfs("/var/lib/cloud8021x/collector", &fs) != nil || uint64(fs.Type) != 0xef53 || fs.Bsize <= 0 {
		return out, errors.New("actual ext4 capacity unavailable")
	}
	out.CapacityBytes = fs.Blocks * uint64(fs.Bsize)
	if out.CapacityBytes == 0 || out.CapacityBytes > out.Bytes {
		return out, errors.New("collector capacity differs")
	}
	return out, nil
}
