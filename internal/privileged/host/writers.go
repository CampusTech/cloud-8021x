package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Names come from the retained startup.sh and radius_usage_service.py. Never
// accept caller-selected units, scripts, lockfiles or privileged output paths.
var legacyWriterUnits = []string{"radius-source-refresh.timer", "radius-cert-renew.timer", "renew-webhook-tls.timer", "radius-source-refresh.service", "radius-source-secrets.service", "radius-cert-renew.service", "renew-webhook-tls.service", "radius-usage-collector.service"}
var legacyWriterCrons = []string{"/etc/cron.d/fleet-device-cache", "/etc/cron.d/unifi-ap-cache", "/etc/cron.d/meraki-ap-cache", "/etc/cron.d/radius-vlan-names"}
var legacyWriterHelpers = []string{"/usr/local/bin/fleet-device-cache.sh", "/usr/local/bin/unifi-ap-cache.sh", "/usr/local/bin/meraki-ap-cache.sh"}
var legacyWriterLocks = []string{"/var/lib/cloud-8021x/fleet-cache.lock", "/run/radius-sources.lock", "/var/lib/radius-usage/checkpoint.json.lock", "/var/lib/radius-usage/checkpoint.json.runner.lock"}

func writerUnitPaths(units []string) []string {
	paths := make([]string, len(units))
	for i, u := range units {
		paths[i] = "/etc/systemd/system/" + u
	}
	return paths
}
func legacyWriterFile(path string) bool {
	return slices.Contains(legacyWriterCrons, path) || slices.Contains(legacyWriterHelpers, path) || slices.Contains(writerUnitPaths(legacyWriterUnits), path)
}

type writerReceipt struct {
	Version                        int
	Transition, Node, ConfigSHA256 string
	Files                          []SavedFile
	Masks                          []string
}

func writerReceiptDirectory(id string) (string, error) {
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(id) {
		return "", errors.New("invalid protected writer transition")
	}
	return filepath.Join(transactionRoot, "writers", id), nil
}
func writerUnitsQuiescent(ctx context.Context, run commandRunner, units []string) error {
	for _, unit := range units {
		data, e := run(ctx, "/usr/bin/systemctl", "show", unit, "--property=ActiveState", "--property=SubState", "--property=MainPID")
		if e != nil {
			return errors.New("writer unit state unavailable")
		}
		values := map[string]string{}
		for _, line := range strings.Split(string(data), "\n") {
			k, v, _ := strings.Cut(line, "=")
			values[k] = v
		}
		if values["ActiveState"] != "inactive" || values["SubState"] != "dead" || values["MainPID"] != "0" {
			return errors.New("legacy writer not proven stopped")
		}
	}
	return nil
}
func FenceLegacyWriters(ctx context.Context, id, node, configSHA string) (string, error) {
	return fenceLegacyWriters(ctx, id, node, configSHA, execute, legacyProcessesQuiescent)
}
func fenceLegacyWriters(ctx context.Context, id, node, configSHA string, run commandRunner, probe func() error) (string, error) {
	directory, err := writerReceiptDirectory(id)
	if err != nil {
		return "", err
	}
	if os.Geteuid() != 0 || (node != "radius-primary" && node != "radius-secondary") || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(configSHA) {
		return "", errors.New("root fixed writer fence required")
	}
	if err = protectedDirectory(directory, 0, 0, 0700); err != nil {
		return "", err
	}
	receiptPath := filepath.Join(directory, "receipt.json")
	data, err := readPrivateCache(receiptPath, 16<<20)
	if err == nil {
		var receipt writerReceipt
		if json.Unmarshal(data, &receipt) != nil || receipt.Version != 1 || receipt.Transition != id || receipt.Node != node || receipt.ConfigSHA256 != configSHA {
			return "", errors.New("writer fence receipt mismatch")
		}
		sum := sha256.Sum256(data)
		digest := hex.EncodeToString(sum[:])
		completed, e := readPrivateCache(filepath.Join(directory, "complete"), 128)
		if e != nil || string(completed) != digest {
			return "", errors.New("interrupted writer fence requires root evidence reconciliation")
		}
		if e = verifyWriterMasks(); e != nil {
			return "", e
		}
		if e = writerUnitsQuiescent(ctx, run, legacyWriterUnits); e != nil {
			return "", e
		}
		if e = probe(); e != nil {
			return "", e
		}
		return digest, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	receipt := writerReceipt{Version: 1, Transition: id, Node: node, ConfigSHA256: configSHA}
	paths := append(append(append([]string{}, legacyWriterCrons...), legacyWriterHelpers...), writerUnitPaths(legacyWriterUnits)...)
	for _, path := range paths {
		if target, e := os.Readlink(path); e == nil {
			if target != "/dev/null" || !slices.Contains(writerUnitPaths(legacyWriterUnits), path) {
				return "", errors.New("unrecognized legacy writer symlink")
			}
			receipt.Masks = append(receipt.Masks, path)
			continue
		}
		if e := PrepareFileDirectories([]File{{Path: path}}); e != nil {
			return "", e
		}
		saved, e := Snapshot(File{Path: path})
		if e != nil {
			return "", e
		}
		if filepath.Base(path) == "radius-usage-collector.service" && saved.Exists && !bytes.Contains(saved.Data, []byte("# Managed radius usage monitor; does not control FreeRADIUS.\n")) {
			return "", errors.New("unmanaged usage service refused")
		}
		receipt.Files = append(receipt.Files, saved)
	}
	data, err = json.Marshal(receipt)
	if err != nil {
		return "", err
	}
	if err = privateWrite(receiptPath, data, 0600); err != nil {
		return "", err
	}
	if err = syncWriterDirectory(directory); err != nil {
		return "", err
	}
	// Snapshots are now durable. A crash from here is uncertain and cannot silently
	// overwrite these originals on the next run.
	for _, path := range legacyWriterHelpers {
		if err = Write(File{Path: path, Data: []byte("#!/bin/sh\n# cloud-8021x legacy writer fenced\nexit 0\n"), Mode: 0755}); err != nil {
			return "", err
		}
	}
	for _, path := range legacyWriterCrons {
		if err = Write(File{Path: path, Data: []byte("# cloud-8021x legacy writer fenced\n"), Mode: 0644}); err != nil {
			return "", err
		}
	}
	for _, path := range writerUnitPaths(legacyWriterUnits) {
		if err = maskWriterUnit(path); err != nil {
			return "", err
		}
	}
	if _, err = run(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
		return "", err
	}
	for _, unit := range legacyWriterUnits {
		if _, err = run(ctx, "/usr/bin/systemctl", "stop", unit); err != nil {
			return "", err
		}
	}
	if err = writerUnitsQuiescent(ctx, run, legacyWriterUnits); err != nil {
		return "", err
	}
	unlock, err := lockLegacyWriters()
	if err != nil {
		return "", err
	}
	defer unlock()
	if err = probe(); err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	if err = privateWrite(filepath.Join(directory, "complete"), []byte(digest), 0600); err != nil {
		return "", err
	}
	if err = syncWriterDirectory(directory); err != nil {
		return "", err
	}
	return digest, nil
}
func syncWriterDirectory(path string) error {
	d, e := os.Open(path)
	if e != nil {
		return e
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
func maskWriterUnit(path string) error {
	dir, e := parentDescriptor(path, 0, false)
	if e != nil {
		return e
	}
	defer func() { _ = unix.Close(dir) }()
	name := filepath.Base(path)
	target, e := os.Readlink(path)
	if e == nil {
		if target == "/dev/null" {
			return nil
		}
		return errors.New("unrecognized writer mask")
	}
	// Snapshot and protected parent prevent attacker-selected targets. Rename the
	// fixed /dev/null symlink atomically over the original root regular unit.
	temp := ".cloud8021x-mask-" + name
	if e = unix.Symlinkat("/dev/null", dir, temp); e != nil {
		return e
	}
	defer func() { _ = unix.Unlinkat(dir, temp, 0) }()
	if e = unix.Renameat(dir, temp, dir, name); e != nil {
		return e
	}
	return unix.Fsync(dir)
}
func verifyWriterMasks() error {
	for _, path := range writerUnitPaths(legacyWriterUnits) {
		dir, e := parentDescriptor(path, 0, false)
		if e != nil {
			return e
		}
		_ = unix.Close(dir)
		target, e := os.Readlink(path)
		if e != nil || target != "/dev/null" {
			return errors.New("persistent writer mask changed")
		}
	}
	for _, path := range append(append([]string{}, legacyWriterCrons...), legacyWriterHelpers...) {
		saved, e := Snapshot(File{Path: path})
		if e != nil || !saved.Exists || !bytes.Contains(saved.Data, []byte("cloud-8021x legacy writer fenced")) {
			return errors.New("legacy scheduled writer fence changed")
		}
	}
	return nil
}
func lockLegacyWriters() (func(), error) {
	fds := []int{}
	release := func() {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
	}
	for _, path := range legacyWriterLocks {
		fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if errors.Is(e, unix.ENOENT) {
			continue
		}
		if e != nil {
			release()
			return nil, errors.New("legacy writer lock unavailable")
		}
		fds = append(fds, fd)
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&0022 != 0 || unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
			release()
			return nil, errors.New("legacy writer lock not quiescent")
		}
	}
	return release, nil
}
func legacyProcessesQuiescent() error {
	dir, e := os.Open("/proc")
	if e != nil {
		return errors.New("process quiescence unavailable")
	}
	defer func() { _ = dir.Close() }()
	names, e := dir.Readdirnames(100001)
	if e != nil && !errors.Is(e, io.EOF) || len(names) > 100000 {
		return errors.New("process inventory unavailable")
	}
	scripts := append(append([]string{}, legacyWriterHelpers...), "/etc/freeradius/3.0/mods-config/python3/radius_sources.py", "/etc/freeradius/3.0/mods-config/python3/vlan_names.py", "/usr/local/bin/radius-cert-renew.sh", "/usr/local/sbin/renew-webhook-tls", "radius_usage_service.py", "radius_usage_collector.py")
	for _, name := range names {
		if _, e = strconv.Atoi(name); e != nil {
			continue
		}
		data, e := os.ReadFile(filepath.Join("/proc", name, "cmdline"))
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil || len(data) > 64<<10 {
			return errors.New("process evidence unavailable")
		}
		for _, arg := range strings.Split(string(data), "\x00") {
			for _, script := range scripts {
				if arg == script || filepath.Base(arg) == script {
					return errors.New("legacy writer process still active")
				}
			}
		}
	}
	return nil
}

// Restore restores bytes/modes/absence but never starts an old service. The root
// caller must first revoke the transition, prove both Go workers quiescent, and
// export their final state. Native queues/CA data are untouched.
func RestoreLegacyWriterFiles(id string) error { return restoreLegacyWriterFiles(id, execute) }
func restoreLegacyWriterFiles(id string, run commandRunner) error {
	if os.Geteuid() != 0 {
		return errors.New("root writer rollback required")
	}
	directory, e := writerReceiptDirectory(id)
	if e != nil {
		return e
	}
	data, e := readPrivateCache(filepath.Join(directory, "receipt.json"), 16<<20)
	if e != nil {
		return e
	}
	var receipt writerReceipt
	if json.Unmarshal(data, &receipt) != nil || receipt.Version != 1 || receipt.Transition != id {
		return errors.New("invalid writer rollback receipt")
	}
	if e = verifyWriterMasks(); e != nil {
		return e
	}
	for _, saved := range receipt.Files {
		if !legacyWriterFile(saved.Path) {
			return errors.New("unrecognized writer rollback path")
		}
		if slices.Contains(writerUnitPaths(legacyWriterUnits), saved.Path) {
			dir, e := parentDescriptor(saved.Path, 0, false)
			if e != nil {
				return e
			}
			e = unix.Unlinkat(dir, filepath.Base(saved.Path), 0)
			if e == nil {
				e = unix.Fsync(dir)
			}
			_ = unix.Close(dir)
			if e != nil {
				return e
			}
		}
		if e = Restore(saved); e != nil {
			return e
		}
	}
	_, e = run(context.Background(), "/usr/bin/systemctl", "daemon-reload")
	return e
}
