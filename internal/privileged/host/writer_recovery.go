package host

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"

	"golang.org/x/sys/unix"
)

// AcquireWriterOperation starts before the original maintenance attempt. Its
// nonblocking protected flock is also mandatory for explicit recovery: lease
// expiry cannot prove an old privileged helper has stopped executing.
func AcquireWriterOperation() (func(), error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("root writer operation required")
	}
	const dir = "/run/cloud-8021x-root"
	if e := protectedDirectory(dir, 0, 0, 0700); e != nil {
		return nil, e
	}
	fd, e := unix.Open(dir+"/writer-fence.lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if e != nil {
		return nil, e
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&07777 != 0600 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		_ = unix.Close(fd)
		return nil, errors.New("original writer operation not proven quiescent")
	}
	return func() { _ = unix.Close(fd) }, nil
}
func validateRecoverableWriterFile(old, now SavedFile) error {
	if old.Path != now.Path {
		return errors.New("writer recovery path mismatch")
	}
	if old.Exists == now.Exists && bytes.Equal(old.Data, now.Data) && old.UID == now.UID && old.GID == now.GID && old.Mode == now.Mode {
		return nil
	}
	data, mode := inertCron, uint32(0644)
	if slices.Contains(legacyWriterHelpers, old.Path) {
		data, mode = inertHelper, 0755
	} else if old.Path == legacyVLANModule {
		var e error
		data, e = inertVLANModule(old.Data)
		if e != nil {
			return e
		}
	} else if !slices.Contains(legacyWriterCrons, old.Path) {
		return errors.New("unknown recovery file")
	}
	if !now.Exists || now.UID != 0 || now.GID != 0 || now.Mode != mode || !bytes.Equal(now.Data, data) {
		return errors.New("writer recovery file differs from original and fixed fence")
	}
	return nil
}

// Recovery prevalidates the ENTIRE immutable receipt before finishing any fixed
// replacement. Caller holds AcquireWriterOperation and the exact resumed gate.
func RecoverLegacyWriterFence(ctx context.Context, id, node, hash string) (string, error) {
	return recoverLegacyWriterFence(ctx, id, node, hash, execute)
}
func recoverLegacyWriterFence(ctx context.Context, id, node, hash string, run commandRunner) (string, error) {
	if os.Geteuid() != 0 {
		return "", errors.New("root recovery required")
	}
	dir, e := writerReceiptDirectory(id)
	if e != nil {
		return "", e
	}
	data, e := readPrivateCache(filepath.Join(dir, "receipt.json"), 16<<20)
	if e != nil {
		return "", e
	}
	r, e := decodeWriterReceipt(data, id)
	if e != nil {
		return "", e
	}
	if r.Node != node || r.ConfigSHA256 != hash || r.Helper.PID <= 0 || r.Helper.Start == 0 {
		return "", errors.New("recovery original identity unavailable")
	}
	processes, e := scanWriterProcesses()
	if e != nil {
		return "", e
	}
	for _, p := range processes {
		if p.PID == r.Helper.PID && p.Start == r.Helper.Start {
			return "", errors.New("original helper still alive")
		}
	}
	// Pin the old directory identities, allowing only the exact saved or protected
	// ownership. This pass does not chown or alter a partially completed operation.
	for _, d := range r.Directories {
		parent, e := writerParent(d.Path, r.NativeUID)
		if e != nil {
			return "", e
		}
		var st unix.Stat_t
		e = unix.Fstatat(parent, filepath.Base(d.Path), &st, unix.AT_SYMLINK_NOFOLLOW)
		_ = unix.Close(parent)
		if e != nil || uint64(st.Dev) != d.Device || uint64(st.Ino) != d.Inode || st.Mode&unix.S_IFMT != unix.S_IFDIR || int(st.Gid) != d.GID || ((int(st.Uid) != d.UID || uint32(st.Mode)&0777 != d.Mode) && (st.Uid != 0 || uint32(st.Mode)&0777 != writerDirectoryMode(d, r.NativeUID))) {
			return "", errors.New("recovery lineage changed")
		}
	}
	for _, old := range r.Files {
		if slices.Contains(writerUnitPaths(legacyWriterUnits), old.Path) {
			if target, e := os.Readlink(old.Path); e == nil {
				if target != "/dev/null" {
					return "", errors.New("foreign recovery mask")
				}
				continue
			}
		}
		var now SavedFile
		if old.Path == legacyVLANModule {
			now, e = snapshotVLANRecovery(r.NativeUID)
		} else {
			now, e = Snapshot(File{Path: old.Path})
		}
		if e != nil {
			return "", e
		}
		if slices.Contains(writerUnitPaths(legacyWriterUnits), old.Path) {
			if old.Exists != now.Exists || !bytes.Equal(old.Data, now.Data) || old.UID != now.UID || old.GID != now.GID || old.Mode != now.Mode {
				return "", errors.New("writer unit changed")
			}
		} else if e = validateRecoverableWriterFile(old, now); e != nil {
			return "", e
		}
	}
	for _, p := range r.Masks {
		if target, e := os.Readlink(p); e != nil || target != "/dev/null" {
			return "", errors.New("original mask changed")
		}
	}
	if done, e := readPrivateCache(filepath.Join(dir, "complete"), 128); e == nil && string(done) != digestBytes(data) {
		return "", errors.New("completion evidence changed")
	} else if e != nil && !errors.Is(e, os.ErrNotExist) {
		return "", e
	}
	return finishWriterFence(ctx, dir, r, data, run, func() error { return checkObservedWriterProcesses(r.Processes) })
}
func snapshotVLANRecovery(uid int) (SavedFile, error) {
	// snapshotVLAN normally also validates the original CLI tail. Recovery accepts
	// either original or inert bytes, then compares the full bytes against receipt.
	return snapshotVLANWithTail(uid, false)
}
