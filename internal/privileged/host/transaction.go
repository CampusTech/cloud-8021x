package host

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Activation is the small installed-backend contract. Running must distinguish
// positively stopped from unknown. PeerReady authenticates policy/config/certs,
// in addition to the native RADIUS response, before a functioning node restarts.
type Activation interface {
	Running(context.Context) (bool, error)
	PeerReady(context.Context) error
	Validate(context.Context) error
	Activate(context.Context) error
	Healthy(context.Context) error
}

func CheckRestart(ctx context.Context, b Activation) error {
	if b == nil {
		return errors.New("activation backend unavailable")
	}
	active, e := b.Running(ctx)
	if e != nil {
		return errors.New("local backend state unknown; restart refused")
	}
	if active {
		if e = b.PeerReady(ctx); e != nil {
			return errors.New("authenticated peer readiness required before active restart")
		}
	}
	return nil
}
func ActivateValidated(ctx context.Context, b Activation) error {
	if e := b.Validate(ctx); e != nil {
		return errors.New("candidate backend configuration rejected")
	}
	if e := CheckRestart(ctx, b); e != nil {
		return e
	}
	if e := b.Activate(ctx); e != nil {
		return errors.New("backend activation failed")
	}
	return b.Healthy(ctx)
}

const transactionRoot = "/var/lib/cloud-8021x-bootstrap"
const radiusParent = "/etc/freeradius"
const radiusDirectory = radiusParent + "/3.0"

// Receipt retains exact prior files and the entire prior Debian config tree.
// Packaged root-owned symlinks are retained in that tree, never followed/rewritten.
// Private backups remain root-only; neither daemon nor native roles can read them.
type Receipt struct {
	Native               map[string]string `json:"native,omitempty"`
	RadiusManifestSHA256 string            `json:"radius_manifest_sha256,omitempty"`
	WriterRetirement     *writerRetirement `json:"writer_retirement,omitempty"`
	PackageBarrier       bool              `json:"package_barrier"`
	WasRunning           bool              `json:"was_running"`
	ID                   string            `json:"id"`
	Phase                string            `json:"phase"`
	HadRadius            bool              `json:"had_radius"`
	TreeSaved            bool              `json:"tree_saved"`
	TreeSwapped          bool              `json:"tree_swapped"`
	Packages             *PackagePlan      `json:"packages,omitempty"`
	Files                []SavedFile       `json:"files"`
}
type Transaction struct {
	committed       bool
	rollbackBackend Activation
	receipt         Receipt
	directory       string
	tree            map[string][]byte
	files           []File
}

func protectedDirectory(path string, uid, gid int, mode uint32) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("invalid installed directory")
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		final := i == len(parts)-1
		createMode := uint32(0755)
		if final {
			createMode = mode
		}
		e = unix.Mkdirat(fd, part, createMode)
		if e != nil && !errors.Is(e, unix.EEXIST) {
			_ = unix.Close(fd)
			return e
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if e != nil {
			return errors.New("unsafe installed directory")
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Mode&0022 != 0 || (st.Uid != 0 && (!final || int(st.Uid) != uid)) {
			_ = unix.Close(fd)
			return errors.New("unsafe installed directory ownership")
		}
		if final {
			if e = unix.Fchown(fd, uid, gid); e == nil {
				e = unix.Fchmod(fd, mode)
			}
			if e != nil {
				_ = unix.Close(fd)
				return e
			}
		}
	}
	return unix.Close(fd)
}
func privateWrite(path string, data []byte, mode os.FileMode) error {
	// All callers use random root-owned staging directories established above.
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if e != nil {
		return e
	}
	_, e = f.Write(data)
	if e == nil {
		e = f.Sync()
	}
	return errors.Join(e, f.Close())
}
func (t *Transaction) persist(phase string) error {
	t.receipt.Phase = phase
	data, e := json.Marshal(t.receipt)
	if e != nil {
		return e
	}
	path := filepath.Join(t.directory, "receipt.json")
	temp := path + ".next"
	if e = privateWrite(temp, data, 0600); e != nil {
		return e
	}
	if e = os.Rename(temp, path); e != nil {
		return e
	}
	fd, e := unix.Open(t.directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	defer func() { _ = unix.Close(fd) }()
	return unix.Fsync(fd)
}

// PrepareTransaction completes backups and staging before any live config change.
// record persists the exact nonsecret transaction ID in root-private shared PG
// maintenance state before returning; an uncertain record prevents installation.
func BeginTransaction(record func(string) error) (*Transaction, error) {
	if os.Geteuid() != 0 || record == nil {
		return nil, errors.New("root transaction dependencies missing")
	}
	if e := protectedDirectory(transactionRoot, 0, 0, 0700); e != nil {
		return nil, e
	}
	var nonce [16]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return nil, e
	}
	id := hex.EncodeToString(nonce[:])
	t := &Transaction{receipt: Receipt{ID: id}, directory: filepath.Join(transactionRoot, id)}
	if e := protectedDirectory(t.directory, 0, 0, 0700); e != nil {
		return nil, e
	}
	if e := t.persist("planning"); e != nil {
		return nil, e
	}
	if e := record(id); e != nil {
		return nil, errors.New("shared installation receipt uncertain; activation withheld")
	}
	return t, nil
}
func PrepareTransaction(tree map[string][]byte, files []File, record func(string) error) (*Transaction, error) {
	t, e := BeginTransaction(record)
	if e != nil {
		return nil, e
	}
	if e = t.Prepare(tree, files); e != nil {
		return nil, e
	}
	return t, nil
}
func (t *Transaction) Prepare(tree map[string][]byte, files []File) error {
	if t == nil || len(tree) == 0 || (t.receipt.Phase != "planning" && t.receipt.Phase != "packages-installed") {
		return errors.New("installation cannot be staged")
	}
	t.tree, t.files = tree, files
	t.receipt.Native = map[string]string{}
	for p, data := range tree {
		t.receipt.Native[p] = digestBytes(data)
	}
	if t.receipt.WriterRetirement != nil {
		t.receipt.WriterRetirement.Native = map[string]string{}
		for p, data := range tree {
			t.receipt.WriterRetirement.Native[p] = digestBytes(data)
		}
	}
	id := t.receipt.ID
	accounts, e := ReadAccounts()
	if e != nil {
		return e
	}
	if e = migrateLegacyDirectory(radiusParent, accounts, t.directory); e != nil {
		return e
	}
	if e = protectedDirectory(radiusParent, 0, 0, 0755); e != nil {
		return e
	}
	stage := filepath.Join(radiusParent, ".cloud8021x-stage-"+id)
	if e := protectedDirectory(stage, 0, 0, 0750); e != nil {
		return e
	}
	if e = protectedDirectory(stage, 0, accounts.NativeGID, 0750); e != nil {
		return e
	}
	names := make([]string, 0, len(tree))
	for name := range tree {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !AllowedFile(radiusDirectory+"/"+name) || strings.Contains(name, "..") || strings.HasPrefix(name, "/") || len(tree[name]) > 16<<20 {
			return errors.New("unapproved complete RADIUS configuration file")
		}
		path := filepath.Join(stage, name)
		if e := protectedDirectory(filepath.Dir(path), 0, accounts.NativeGID, 0750); e != nil {
			return e
		}
		mode := os.FileMode(0600)
		if strings.HasPrefix(name, "certs/") {
			mode = 0640
		}
		if e := privateWrite(path, tree[name], mode); e != nil {
			return e
		}
		if strings.HasPrefix(name, "certs/") {
			if e := os.Chown(path, 0, accounts.NativeGID); e != nil {
				return e
			}
		}
	}
	for _, file := range files {
		saved, e := Snapshot(file)
		if e != nil {
			return e
		}
		t.receipt.Files = append(t.receipt.Files, saved)
	}
	if e = t.snapshotRadius(context.Background()); e != nil {
		return e
	}
	if e = t.persist("prepared"); e != nil {
		return e
	}
	return nil
}
func (t *Transaction) Reference() string { return t.receipt.ID }

// Apply preserves the prior complete tree by rename, including Debian's packaged
// symlink topology. The running server stays alive throughout validation. The
// final -XC uses final paths; only a validated candidate reaches service activation.
func (t *Transaction) Apply(ctx context.Context, b Activation) error {
	if t == nil || t.receipt.Phase != "prepared" {
		return errors.New("installation is not prepared")
	}
	if e := CheckRestart(ctx, b); e != nil {
		return e
	}
	if e := t.persist("applying"); e != nil {
		return e
	}
	t.receipt.TreeSwapped = true
	if e := t.persist("applying"); e != nil {
		return e
	}
	if _, e := os.Lstat(radiusDirectory); e == nil {
		if e = os.Rename(radiusDirectory, filepath.Join(radiusParent, ".cloud8021x-displaced-"+t.receipt.ID)); e != nil {
			return e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e := os.Rename(filepath.Join(radiusParent, ".cloud8021x-stage-"+t.receipt.ID), radiusDirectory); e != nil {
		return errors.Join(e, t.Rollback(ctx, b, false))
	}
	if _, e := execute(ctx, "/usr/bin/sync", "--file-system", radiusParent); e != nil {
		return errors.Join(e, t.Rollback(ctx, b, false))
	}
	for _, file := range t.files {
		if e := Write(file); e != nil {
			return errors.Join(e, t.Rollback(ctx, b, false))
		}
	}
	if e := b.Validate(ctx); e != nil {
		return errors.Join(errors.New("candidate configuration rejected"), t.Rollback(ctx, b, false))
	}
	if e := CheckRestart(ctx, b); e != nil {
		return errors.Join(e, t.Rollback(ctx, b, false))
	}
	if e := t.persist("activating"); e != nil {
		return e
	}
	if e := t.activate(ctx, b); e != nil {
		return errors.Join(e, t.Rollback(ctx, b, true))
	}
	if e := b.Healthy(ctx); e != nil {
		return errors.Join(e, t.Rollback(ctx, b, true))
	}
	return t.persist("complete")
}
func (t *Transaction) Rollback(ctx context.Context, b Activation, restart bool) error {
	if t == nil {
		return errors.New("missing rollback receipt")
	}
	if t.committed {
		return errors.New("completed installation cannot be rolled back by a reporting failure")
	}
	if t.receipt.Phase == "rolled-back" {
		return nil
	}
	// Caller cancellation cannot interrupt an already necessary rollback, but each
	// host action and the complete rollback remain explicitly bounded.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Minute)
	defer cancel()
	activationStarted := restart || t.receipt.Phase == "activating" || t.receipt.Phase == "complete"
	if backend, ok := b.(*RadiusBackend); ok && activationStarted {
		if t.receipt.WasRunning {
			if e := backend.Quiesce(ctx); e != nil {
				return e
			}
		} else {
			if e := backend.stopOwnedStart(ctx); e != nil {
				return e
			}
		}
		if t.rollbackBackend == nil {
			if e := backend.stopCompanions(ctx); e != nil {
				return e
			}
		}
	}
	if t.receipt.Packages != nil && t.receipt.Packages.Changed {
		if backend, ok := b.(*RadiusBackend); ok && !t.receipt.PackageBarrier {
			if e := t.MaskPackages(ctx, backend); e != nil {
				return e
			}
		}
		if e := t.receipt.Packages.Rollback(ctx); e != nil {
			return e
		}
	}
	if t.receipt.TreeSwapped || t.receipt.Packages != nil {
		if t.receipt.WriterRetirement != nil && !activationStarted {
			if backend, ok := b.(*RadiusBackend); ok {
				if e := backend.Quiesce(ctx); e != nil {
					return e
				}
			}
		}
		if e := t.restoreRadius(ctx); e != nil {
			return e
		}
	}
	for i := len(t.receipt.Files) - 1; i >= 0; i-- {
		if e := Restore(t.receipt.Files[i]); e != nil {
			return e
		}
	}
	if e := t.restoreLegacyOwnership(); e != nil {
		return e
	}
	if t.receipt.TreeSwapped || t.receipt.Packages != nil {
		if e := t.recordRollbackLineage(); e != nil {
			return e
		}
	}
	if t.receipt.WasRunning && t.rollbackBackend != nil && (activationStarted || (t.receipt.Packages != nil && t.receipt.Packages.Changed)) {
		if e := t.rollbackBackend.Validate(ctx); e != nil {
			return e
		}
		if e := t.activate(ctx, t.rollbackBackend); e != nil {
			return e
		}
		if e := t.rollbackBackend.Healthy(ctx); e != nil {
			return e
		}
	}
	if backend, ok := b.(*RadiusBackend); ok && t.receipt.PackageBarrier {
		if e := t.UnmaskPackages(ctx, backend); e != nil {
			return e
		}
	}
	return t.persist("rolled-back")
}

func (t *Transaction) MaskPackages(ctx context.Context, b *RadiusBackend) error {
	t.receipt.PackageBarrier = true
	if err := t.persist(t.receipt.Phase); err != nil {
		return err
	}
	return b.PackageBarrier(ctx)
}
func (t *Transaction) UnmaskPackages(ctx context.Context, b *RadiusBackend) error {
	if !t.receipt.PackageBarrier {
		return nil
	}
	if err := b.RemovePackageBarrier(ctx); err != nil {
		return err
	}
	t.receipt.PackageBarrier = false
	return t.persist(t.receipt.Phase)
}

// Runtime masking prevents the daemon's fixed Wants=freeradius boot/recovery
// relationship from starting native during a guarded dependency replacement.
// Release is journaled only after policy, both CAs and collector are ready.
func (t *Transaction) activate(ctx context.Context, b Activation) error {
	if backend, ok := b.(*RadiusBackend); ok && backend.Companions {
		if !t.receipt.PackageBarrier {
			if e := t.MaskPackages(ctx, backend); e != nil {
				return e
			}
		}
		backend.releaseBarrier = func(ctx context.Context) error { return t.UnmaskPackages(ctx, backend) }
		defer func() { backend.releaseBarrier = nil }()
	}
	return b.Activate(ctx)
}
