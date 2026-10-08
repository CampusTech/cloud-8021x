package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// Names come from the retained startup.sh and radius_usage_service.py. Never
// accept caller-selected units, scripts, lockfiles or privileged output paths.
var legacyWriterUnits = []string{"radius-source-refresh.timer", "radius-cert-renew.timer", "renew-webhook-tls.timer", "radius-source-refresh.service", "radius-source-secrets.service", "radius-cert-renew.service", "renew-webhook-tls.service", "radius-usage-collector.service"}
var legacyWriterCrons = []string{"/etc/cron.d/fleet-device-cache", "/etc/cron.d/jamf-device-cache", "/etc/cron.d/unifi-ap-cache", "/etc/cron.d/meraki-ap-cache", "/etc/cron.d/radius-vlan-names"}
var legacyWriterHelpers = []string{"/usr/local/bin/fleet-device-cache.sh", "/usr/local/bin/fleet-device-fetch.sh", "/usr/local/bin/jamf-device-cache.sh", "/usr/local/bin/jamf-device-fetch.sh", "/usr/local/bin/unifi-ap-cache.sh", "/usr/local/bin/meraki-ap-cache.sh"}
var legacyWriterLocks = []string{"/var/lib/cloud-8021x/fleet-cache.lock", "/etc/freeradius/3.0/vlan-name-cache.json.lock", "/run/radius-sources.lock", "/var/lib/radius-usage/checkpoint.json.lock", "/var/lib/radius-usage/checkpoint.json.runner.lock"}

func writerUnitPaths(units []string) []string {
	paths := make([]string, len(units))
	for i, u := range units {
		paths[i] = "/etc/systemd/system/" + u
	}
	return paths
}
func legacyWriterFile(path string) bool {
	return path == legacyVLANModule || slices.Contains(legacyWriterCrons, path) || slices.Contains(legacyWriterHelpers, path) || slices.Contains(writerUnitPaths(legacyWriterUnits), path)
}

type writerReceipt struct {
	Version                        int
	Transition, Node, ConfigSHA256 string
	Files                          []SavedFile
	Masks                          []string
	NativeUID                      int
	Directories                    []writerDirectory
	Processes                      []writerPID
	Helper                         writerPID
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
			if line == "" {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok || (k != "ActiveState" && k != "SubState" && k != "MainPID") {
				return errors.New("unknown writer unit evidence")
			}
			if _, seen := values[k]; seen {
				return errors.New("ambiguous writer unit evidence")
			}
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
		receipt, decodeErr := decodeWriterReceipt(data, id)
		if decodeErr != nil || receipt.Node != node || receipt.ConfigSHA256 != configSHA {
			return "", errors.New("writer fence receipt mismatch")
		}
		sum := sha256.Sum256(data)
		digest := hex.EncodeToString(sum[:])
		completed, e := readPrivateCache(filepath.Join(directory, "complete"), 128)
		if e != nil || string(completed) != digest {
			return "", errors.New("interrupted writer fence requires root evidence reconciliation")
		}
		if e = verifyWriterMasks(receipt); e != nil {
			return "", e
		}
		if e = writerUnitsQuiescent(ctx, run, legacyWriterUnits); e != nil {
			return "", e
		}
		unlock, e := lockLegacyWriters()
		if e != nil {
			return "", e
		}
		defer unlock()
		if e = probe(); e != nil {
			return "", e
		}
		return digest, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	receipt := writerReceipt{Version: 1, Transition: id, Node: node, ConfigSHA256: configSHA}
	receipt.Directories, receipt.NativeUID, err = snapshotWriterLineage()
	if err != nil {
		return "", err
	}
	processes, err := scanWriterProcesses()
	if err != nil {
		return "", err
	}
	receipt.Processes = writerProcessEvidence(processes)
	for _, p := range processes {
		if p.PID == os.Getpid() {
			receipt.Helper = writerPID{p.PID, p.Start}
		}
	}
	if receipt.Helper.Start == 0 {
		return "", errors.New("writer helper process identity unavailable")
	}
	paths := legacyWriterPaths()
	for _, path := range paths {
		if path == legacyVLANModule {
			saved, e := snapshotVLAN(receipt.NativeUID)
			if e != nil {
				return "", e
			}
			receipt.Files = append(receipt.Files, saved)
			continue
		}
		if e := PrepareFileDirectories([]File{{Path: path}}); e != nil {
			return "", e
		}
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
	if err == nil {
		_, err = decodeWriterReceipt(data, id)
	}
	if err != nil {
		return "", err
	}
	if err = privateWrite(receiptPath, data, 0600); err != nil {
		return "", err
	}
	if err = syncWriterDirectory(directory); err != nil {
		return "", err
	}
	return finishWriterFence(ctx, directory, receipt, data, run, probe)
}
func finishWriterFence(ctx context.Context, directory string, receipt writerReceipt, data []byte, run commandRunner, probe func() error) (string, error) {
	var err error
	// Snapshots are now durable. A crash from here is uncertain and cannot silently
	// overwrite these originals on the next run.
	if err = protectWriterLineage(receipt, false); err != nil {
		return "", err
	}
	for _, saved := range receipt.Files {
		if saved.Path == legacyVLANModule && saved.Exists {
			inert, e := inertVLANModule(saved.Data)
			if e != nil {
				return "", e
			}
			if e = Write(File{Path: saved.Path, Data: inert, Mode: 0644, adoptUID: saved.UID}); e != nil {
				return "", e
			}
		}
	}
	for _, path := range legacyWriterHelpers {
		if err = Write(File{Path: path, Data: inertHelper, Mode: 0755}); err != nil {
			return "", err
		}
	}
	for _, path := range legacyWriterCrons {
		if err = Write(File{Path: path, Data: inertCron, Mode: 0644}); err != nil {
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
	if err = verifyWriterMasks(receipt); err != nil {
		return "", err
	}
	if err = probe(); err != nil {
		return "", err
	}
	digest := digestBytes(data)
	if old, e := readPrivateCache(filepath.Join(directory, "complete"), 128); e == nil {
		if string(old) != digest {
			return "", errors.New("writer completion changed")
		}
	} else if errors.Is(e, os.ErrNotExist) {
		if err = privateWrite(filepath.Join(directory, "complete"), []byte(digest), 0600); err != nil {
			return "", err
		}
	} else {
		return "", e
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
	var temporary unix.Stat_t
	if e = unix.Fstatat(dir, temp, &temporary, unix.AT_SYMLINK_NOFOLLOW); e == nil {
		target, e := os.Readlink(filepath.Join(filepath.Dir(path), temp))
		if e != nil || target != "/dev/null" || temporary.Mode&unix.S_IFMT != unix.S_IFLNK || temporary.Uid != 0 || temporary.Gid != 0 {
			return errors.New("unknown interrupted mask temporary")
		}
		if e = unix.Unlinkat(dir, temp, 0); e != nil {
			return e
		}
	} else if !errors.Is(e, unix.ENOENT) {
		return e
	}
	if e = unix.Symlinkat("/dev/null", dir, temp); e != nil {
		return e
	}
	defer func() { _ = unix.Unlinkat(dir, temp, 0) }()
	if e = unix.Renameat(dir, temp, dir, name); e != nil {
		return e
	}
	return unix.Fsync(dir)
}
func verifyWriterMasks(receipt writerReceipt) error {
	if e := verifyWriterLineage(receipt); e != nil {
		return e
	}
	if e := verifyWriterNonNativeMasks(receipt); e != nil {
		return e
	}
	for _, saved := range receipt.Files {
		if saved.Path == legacyVLANModule && saved.Exists {
			expected, e := inertVLANModule(saved.Data)
			if e != nil {
				return e
			}
			current, e := Snapshot(File{Path: legacyVLANModule})
			if e != nil || !current.Exists || !bytes.Equal(current.Data, expected) || current.UID != 0 {
				return errors.New("VLAN writer fence changed")
			}
		}
	}
	return checkObservedWriterProcesses(receipt.Processes)
}
func verifyWriterNonNativeMasks(receipt writerReceipt) error {
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
		expected := inertCron
		if slices.Contains(legacyWriterHelpers, path) {
			expected = inertHelper
		}
		if e != nil || !saved.Exists || !bytes.Equal(saved.Data, expected) {
			return errors.New("legacy scheduled writer fence changed")
		}
	}
	return checkObservedWriterProcesses(receipt.Processes)
}
func lockLegacyWriters() (func(), error) {
	fds := []int{}
	release := func() {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
	}
	for _, path := range legacyWriterLocks {
		parent, e := writerParent(path, 0)
		if errors.Is(e, unix.ENOENT) {
			continue
		}
		if e != nil {
			release()
			return nil, errors.New("legacy lock ancestor unsafe")
		}
		fd, e := unix.Openat(parent, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		_ = unix.Close(parent)
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
func legacyProcessesQuiescent() error { return checkObservedWriterProcesses(nil) }
func checkObservedWriterProcesses(observed []writerPID) error {
	processes, e := scanWriterProcesses()
	if e != nil {
		return e
	}
	return checkWriterProcesses(processes, observed)
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
	receipt, decodeErr := decodeWriterReceipt(data, id)
	if decodeErr != nil {
		return errors.New("invalid writer rollback receipt")
	}
	sum := sha256.Sum256(data)
	completed, err := readPrivateCache(filepath.Join(directory, "complete"), 128)
	if err != nil || string(completed) != hex.EncodeToString(sum[:]) {
		return errors.New("writer completion receipt mismatch")
	}
	if e = verifyWriterMasks(receipt); e != nil {
		return e
	}
	unlock, e := lockLegacyWriters()
	if e != nil {
		return e
	}
	defer unlock()
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
		if saved.Path == legacyVLANModule && !saved.Exists {
			continue
		}
		if e = Restore(saved); e != nil {
			return e
		}
	}
	if e = protectWriterLineage(receipt, true); e != nil {
		return e
	}
	_, e = run(context.Background(), "/usr/bin/systemctl", "daemon-reload")
	return e
}
