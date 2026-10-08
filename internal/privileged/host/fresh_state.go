package host

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/migration"
	"golang.org/x/sys/unix"
)

var freshFootprints = []string{"/etc/freeradius", "/etc/mysql", "/var/lib/mysql", "/run/mysqld", "/var/log/freeradius", "/var/lib/cloud-8021x", "/var/lib/radius-sources", "/var/lib/radius-usage", "/etc/step-ca", "/etc/step-ca-rsa", "/var/lib/step-ca", "/var/lib/step-ca-rsa", "/run/radius-accounting-key", "/usr/sbin/freeradius", "/usr/sbin/mariadbd", "/etc/cloud-8021x/config.yaml", "/var/lib/cloud-8021x-source-state", "/var/lib/cloud-8021x-source-proof"}

type freshAbsence struct {
	Transition, Node, ConfigSHA256, ClassSHA256, MachineSHA256 string
	Paths                                                      []string
}

func absentFixed(path string) error {
	fd, e := openParentDescriptor(path, 0, false)
	if errors.Is(e, unix.ENOENT) {
		return nil
	}
	if e != nil {
		return e
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	e = unix.Fstatat(fd, filepath.Base(path), &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(e, unix.ENOENT) {
		return nil
	}
	return errors.New("prior installation footprint exists or is unknown")
}

// PrepareFreshState runs before any writer replacement. The complete fixed
// absence manifest, machine identity and incoming credentials are immutable.
func PrepareFreshState(id, node, hash string, class []byte) (bool, error) {
	if os.Geteuid() != 0 || len(class) < 32 {
		return false, errors.New("protected pre-provisioned Class required")
	}
	dir, e := writerReceiptDirectory(id)
	if e != nil {
		return false, e
	}
	if _, e = readPrivateCache(filepath.Join(dir, "fresh-original.json"), 32<<10); e == nil {
		return true, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return false, e
	}
	if _, e = os.Lstat("/etc/freeradius"); e == nil {
		return false, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return false, e
	}
	paths := append(slices.Clone(freshFootprints), legacyWriterPaths()...)
	for _, path := range paths {
		if e = absentFixed(path); e != nil {
			return false, e
		}
	}
	if e = legacyProcessesQuiescent(); e != nil {
		return false, e
	}
	machine, e := freshMachineIdentity()
	if e != nil || len(bytes.TrimSpace(machine)) != 32 {
		return false, errors.New("fresh machine identity unavailable")
	}
	proof := freshAbsence{id, node, hash, digestBytes(class), digestBytes(machine), paths}
	raw, e := json.Marshal(proof)
	if e != nil {
		return false, e
	}
	if e = protectedDirectory(dir, 0, 0, 0700); e != nil {
		return false, e
	}
	if e = privateWrite(filepath.Join(dir, "fresh-original.json"), raw, 0600); e != nil {
		return false, e
	}
	return true, syncWriterDirectory(dir)
}
func CaptureFreshState(id, node, hash string, class []byte) ([]byte, error) {
	return captureFreshState(id, node, hash, class, true)
}
func VerifyFreshState(id, node, hash string, class []byte) ([]byte, error) {
	return captureFreshState(id, node, hash, class, false)
}
func captureFreshState(id, node, hash string, class []byte, publish bool) ([]byte, error) {
	dir, e := writerReceiptDirectory(id)
	if e != nil {
		return nil, e
	}
	raw, e := readPrivateCache(filepath.Join(dir, "fresh-original.json"), 32<<10)
	if e != nil {
		return nil, e
	}
	var proof freshAbsence
	machine, e := freshMachineIdentity()
	paths := append(slices.Clone(freshFootprints), legacyWriterPaths()...)
	if e != nil || domain.DecodeJSONStrict(raw, &proof) != nil || proof.Transition != id || proof.Node != node || proof.ConfigSHA256 != hash || proof.ClassSHA256 != digestBytes(class) || proof.MachineSHA256 != digestBytes(machine) || !slices.Equal(proof.Paths, paths) {
		return nil, errors.New("fresh original absence binding changed")
	}
	for _, path := range freshFootprints {
		if e = absentFixed(path); e != nil {
			return nil, e
		}
	}
	receipt, e := readPrivateCache(filepath.Join(dir, "receipt.json"), 16<<20)
	if e != nil {
		return nil, e
	}
	r, e := decodeWriterReceipt(receipt, id)
	if e != nil || r.Node != node || r.ConfigSHA256 != hash || len(r.Masks) > 0 || len(r.Directories) > 0 || r.NativeUID != 0 {
		return nil, errors.New("fresh writer original differs")
	}
	for _, f := range r.Files {
		if f.Exists {
			return nil, errors.New("fresh seed over prior writer")
		}
	}
	if e = verifyWriterMasks(r); e != nil {
		return nil, e
	}
	data, e := migration.FreshBundle(node, digestBytes(class), digestBytes(raw))
	if e != nil {
		return nil, e
	}
	path := filepath.Join(dir, "bundle.json")
	if old, e := readPrivateCache(path, 96<<20); e == nil {
		if !bytes.Equal(old, data) {
			return nil, errors.New("fresh original bundle differs")
		}
		return old, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	if !publish {
		return nil, errors.New("original fresh bundle missing")
	}
	if e = privateWrite(path, data, 0600); e != nil {
		return nil, e
	}
	return data, syncWriterDirectory(dir)
}

type freshInventory struct {
	Transition, Node, ConfigSHA256, BundleSHA256 string
	Snapshot                                     json.RawMessage
	FingerprintEnforced                          bool
	Attempt                                      int64
	Helper                                       writerPID
}

// PrepareFreshInventory archives the original observer response before SQL commit.
// The caller holds the fixed operation flock and the live fresh-initial gate.
func PrepareFreshInventory(id, node, hash, bundle string, snapshot []byte, attempt int64) error {
	if os.Geteuid() != 0 || attempt < 1 {
		return errors.New("protected original fresh attempt required")
	}
	dir, e := writerReceiptDirectory(id)
	if e != nil {
		return e
	}
	if e = protectedDirectory(dir, 0, 0, 0700); e != nil {
		return e
	}
	processes, e := scanWriterProcesses()
	if e != nil {
		return e
	}
	var helper writerPID
	for _, p := range processes {
		if p.PID == os.Getpid() {
			helper = writerPID{p.PID, p.Start}
		}
	}
	if helper.Start == 0 {
		return errors.New("fresh original helper unavailable")
	}
	r := freshInventory{Transition: id, Node: node, ConfigSHA256: hash, BundleSHA256: bundle, Snapshot: snapshot, FingerprintEnforced: true, Attempt: attempt, Helper: helper}
	raw, e := json.Marshal(r)
	if e != nil {
		return e
	}
	path := filepath.Join(dir, "fresh-inventory.json")
	if _, e = readPrivateCache(path, 20<<20); e == nil {
		prior, e := readFreshInventory(StatePublication{Transition: id, Node: node, ConfigSHA256: hash, BundleSHA256: bundle})
		if e != nil {
			return e
		}
		if !bytes.Equal(prior.Snapshot, snapshot) {
			return errors.New("original fresh observer snapshot changed")
		}
		if prior.Attempt == attempt {
			if prior.Helper != helper {
				return errors.New("original helper changed")
			}
			return nil
		}
		if e = ProveFreshInventoryStopped(id, node, hash, bundle, prior.Attempt); e != nil {
			return e
		}
		// A new gate can finish only the original prepared snapshot. Retain the
		// original receipt and append the current helper identity separately.
		path = filepath.Join(dir, fmt.Sprintf("fresh-initial-attempt-%d.json", attempt))
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e = privateWrite(path, raw, 0600); e != nil {
		return e
	}
	return syncWriterDirectory(dir)
}
func ReadFreshInventory(id, node, hash, bundle string) ([]byte, error) {
	r, e := readFreshInventory(StatePublication{Transition: id, Node: node, ConfigSHA256: hash, BundleSHA256: bundle})
	return r.Snapshot, e
}
func ProveFreshInventoryStopped(id, node, hash, bundle string, attempt int64) error {
	r, e := readFreshInventory(StatePublication{Transition: id, Node: node, ConfigSHA256: hash, BundleSHA256: bundle})
	if e != nil {
		return e
	}
	if attempt < 1 {
		return errors.New("exact fresh attempt required")
	}
	if r.Attempt != attempt {
		dir, e := writerReceiptDirectory(id)
		if e != nil {
			return e
		}
		raw, e := readPrivateCache(filepath.Join(dir, fmt.Sprintf("fresh-initial-attempt-%d.json", attempt)), 20<<20)
		if e != nil {
			return e
		}
		var continuation freshInventory
		if domain.DecodeJSONStrict(raw, &continuation) != nil || continuation.Transition != r.Transition || continuation.Node != r.Node || continuation.ConfigSHA256 != r.ConfigSHA256 || continuation.BundleSHA256 != r.BundleSHA256 || !continuation.FingerprintEnforced || continuation.Attempt != attempt || !bytes.Equal(continuation.Snapshot, r.Snapshot) {
			return errors.New("fresh continuation binding changed")
		}
		r = continuation
	}
	if r.Helper.PID < 1 || r.Helper.Start == 0 {
		return errors.New("fresh helper identity unavailable")
	}
	processes, e := scanWriterProcesses()
	if e != nil {
		return e
	}
	for _, p := range processes {
		if p.PID == r.Helper.PID && p.Start == r.Helper.Start {
			return errors.New("original fresh helper still alive")
		}
	}
	return nil
}
func readFreshInventory(p StatePublication) (freshInventory, error) {
	var r freshInventory
	dir, e := writerReceiptDirectory(p.Transition)
	if e != nil {
		return r, e
	}
	raw, e := readPrivateCache(filepath.Join(dir, "fresh-inventory.json"), 20<<20)
	if e != nil {
		return r, e
	}
	if domain.DecodeJSONStrict(raw, &r) != nil || r.Transition != p.Transition || r.Node != p.Node || r.ConfigSHA256 != p.ConfigSHA256 || r.BundleSHA256 != p.BundleSHA256 || !r.FingerprintEnforced || r.Attempt < 1 || r.Helper.PID < 1 || r.Helper.Start == 0 {
		return r, errors.New("protected initial observer receipt differs")
	}
	snapshot, e := domain.DecodeSnapshot(bytes.NewReader(r.Snapshot))
	if e != nil || snapshot.Version != 2 || snapshot.UpdatedAt <= 0 || len(snapshot.Certificates) > 0 || len(snapshot.Identities) == 0 || len(snapshot.HardwareSerials) > 0 {
		return r, errors.New("invalid initial observer snapshot")
	}
	return r, nil
}

func freshMachineIdentity() ([]byte, error) {
	f, e := rootFile("/etc/machine-id", 128)
	if e != nil {
		return nil, e
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}
func HasFreshPreparation(id string) (bool, error) {
	dir, e := writerReceiptDirectory(id)
	if e != nil {
		return false, e
	}
	_, e = readPrivateCache(filepath.Join(dir, "fresh-original.json"), 32<<10)
	if errors.Is(e, os.ErrNotExist) {
		return false, nil
	}
	return e == nil, e
}
