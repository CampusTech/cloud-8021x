package host

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/migration"
	"golang.org/x/sys/unix"
)

func retainedNativeFiles(directory string, uid int) ([]migration.RetainedFile, error) {
	if directory != authDirectory && directory != "/var/log/freeradius/radacct" {
		return nil, errors.New("unapproved native state directory")
	}
	fd, e := openParentDescriptor(filepath.Join(directory, "retained"), uid, false)
	if e != nil {
		return nil, e
	}
	defer func() { _ = unix.Close(fd) }()
	copy, e := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	d := os.NewFile(uintptr(copy), "native-retained")
	names, e := d.Readdirnames(8193)
	_ = d.Close()
	if (e != nil && !errors.Is(e, io.EOF)) || len(names) > 8192 {
		return nil, errors.New("native rollback evidence exceeds file bound")
	}
	sort.Strings(names)
	out := []migration.RetainedFile{}
	var total int64
	for _, name := range names {
		ffd, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if e != nil {
			return nil, e
		}
		f := os.NewFile(uintptr(ffd), "retained-native")
		var before, after, path unix.Stat_t
		if unix.Fstat(ffd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || (before.Uid != 0 && int(before.Uid) != uid) || before.Mode&0022 != 0 {
			_ = f.Close()
			return nil, errors.New("unsafe native rollback file")
		}
		total += before.Size
		if before.Size < 0 || before.Size > 512<<20 || total > 1<<30 {
			_ = f.Close()
			return nil, errors.New("native rollback evidence exceeds byte bound")
		}
		hash := sha256.New()
		n, e := io.Copy(hash, io.LimitReader(f, before.Size+1))
		info, ie := f.Stat()
		valid := unix.Fstat(ffd, &after) == nil && unix.Fstatat(fd, name, &path, unix.AT_SYMLINK_NOFOLLOW) == nil && before.Ino == after.Ino && before.Size == after.Size && before.Ino == path.Ino && before.Dev == path.Dev && before.Size == path.Size
		_ = f.Close()
		if e != nil || ie != nil || n != before.Size || !valid {
			return nil, errors.New("retained native file changed during rollback capture")
		}
		out = append(out, migration.RetainedFile{Name: name, Device: uint64(before.Dev), Inode: before.Ino, Size: before.Size, SHA256: hex.EncodeToString(hash.Sum(nil)), ModifiedAt: json.Number(fmt.Sprintf("%d.%09d", info.ModTime().Unix(), info.ModTime().Nanosecond()))})
	}
	return out, nil
}
func CaptureDaemonState(cfg config.Config, a Accounts, class []byte) ([]byte, error) {
	if os.Geteuid() != 0 || cfg.Paths.InventoryFile != daemonPolicySnapshot || cfg.Paths.MetadataFile != "/var/lib/cloud-8021x/metadata.json" || cfg.Paths.AuthLogDir != authDirectory || cfg.Paths.AccountingSpoolDir != "/var/log/freeradius/radacct" {
		return nil, errors.New("fixed protected current state paths required")
	}
	n := migration.NodeState{Version: 1, Node: cfg.InstanceID, ClassKeySHA256: digestBytes(class), ProviderCaches: map[string]json.RawMessage{}}
	read := func(path string, uid int) (json.RawMessage, error) {
		saved, e := snapshotState(File{Path: path, UID: uid})
		if errors.Is(e, unix.ENOENT) {
			return nil, nil
		}
		if e != nil {
			return nil, e
		}
		if !saved.Exists {
			return nil, nil
		}
		if !json.Valid(saved.Data) {
			return nil, errors.New("current state JSON is invalid")
		}
		return bytes.Clone(saved.Data), nil
	}
	var e error
	if n.Inventory, e = read(daemonPolicySnapshot, a.RuntimeUID); e != nil {
		return nil, e
	}
	if n.Metadata, e = read(cfg.Paths.MetadataFile, a.RuntimeUID); e != nil {
		return nil, e
	}
	if cfg.Network.Discovery.Enabled {
		if cfg.Network.Discovery.CandidateFile != "/var/lib/cloud-8021x/sources-candidate.json" {
			return nil, errors.New("fixed source candidate path required")
		}
		if n.Discovery, e = read(cfg.Network.Discovery.CandidateFile, a.RuntimeUID); e != nil {
			return nil, e
		}
		if n.ProtectedSources, e = read("/var/lib/cloud-8021x-source-state/state.json", 0); e != nil {
			return nil, e
		}
	}
	cache := func(path string) (json.RawMessage, error) {
		if path == "" {
			return nil, nil
		}
		if !strings.HasPrefix(path, "/var/cache/cloud-8021x/runtime/") || filepath.Clean(path) != path {
			return nil, errors.New("fixed runtime cache ancestry required")
		}
		return read(path, a.RuntimeUID)
	}
	if cfg.Inventory.Enabled {
		if n.InventoryCache, e = cache(cfg.Inventory.Fleet.CacheFile); e != nil {
			return nil, e
		}
	}
	for _, provider := range cfg.Network.Providers {
		raw, e := cache(provider.CacheFile)
		if e != nil {
			return nil, e
		}
		if raw != nil {
			n.ProviderCaches[provider.ID] = raw
		}
	}
	guard, e := snapshotState(File{Path: legacyDowngradeGuard, UID: a.RuntimeUID})
	if e != nil {
		return nil, e
	}
	n.FingerprintEnforced = guard.Exists
	if n.AuthFiles, e = retainedNativeFiles(authDirectory, a.NativeUID); e != nil {
		return nil, e
	}
	if n.AccountingFiles, e = retainedNativeFiles(cfg.Paths.AccountingSpoolDir, a.NativeUID); e != nil {
		return nil, e
	}
	raw, e := json.Marshal(n)
	if e != nil {
		return nil, e
	}
	if _, e = migration.DecodeNodeState(raw); e != nil {
		return nil, e
	}
	dir, e := writerReceiptDirectory(cfg.StateTransition)
	if e != nil {
		return nil, e
	}
	path := filepath.Join(dir, "worker-current.json")
	if previous, e := readPrivateCache(path, 64<<20); e == nil {
		if !bytes.Equal(previous, raw) {
			return nil, errors.New("current state differs from original worker fence capture")
		}
		return previous, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	if e = privateWrite(path, raw, 0600); e != nil {
		return nil, e
	}
	if e = syncWriterDirectory(dir); e != nil {
		return nil, e
	}
	return raw, nil
}
