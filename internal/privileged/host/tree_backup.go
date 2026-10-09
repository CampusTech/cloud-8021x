package host

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Snapshot the complete legacy tree before dpkg or managed configuration writes.
// cp -a preserves Debian's symlinks without following them. The enclosing receipt
// directory is root-only, even when original child ownership belongs to freerad.
func (t *Transaction) snapshotRadius(ctx context.Context) error {
	if t.receipt.TreeSaved {
		return nil
	}
	info, err := os.Lstat(radiusDirectory)
	if errors.Is(err, os.ErrNotExist) {
		t.receipt.TreeSaved = true
		return t.persist(t.receipt.Phase)
	}
	if err != nil || !info.IsDir() {
		return errors.New("installed native configuration is not a directory")
	}
	count := 0
	var size int64
	err = filepath.WalkDir(radiusDirectory, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		count++
		if count > 8192 {
			return errors.New("legacy configuration tree exceeds file bound")
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			size += info.Size()
			if size > 64<<20 {
				return errors.New("legacy configuration tree exceeds byte bound")
			}
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			resolved := filepath.Clean(filepath.Join(filepath.Dir(path), target))
			if filepath.IsAbs(target) || !strings.HasPrefix(resolved, radiusDirectory+"/") {
				return errors.New("legacy configuration link escapes tree")
			}
			return nil
		}
		return errors.New("unsupported legacy configuration object")
	})
	if err != nil {
		return err
	}
	var manifest []byte
	if t.receipt.WriterRetirement != nil {
		manifest, err = nativeTreeManifest(radiusDirectory)
		if err != nil {
			return err
		}
		if err = privateWrite(filepath.Join(t.directory, "radius-manifest.json"), manifest, 0600); err != nil {
			return err
		}
		t.receipt.RadiusManifestSHA256 = digestBytes(manifest)
	}
	if _, err = execute(ctx, "/usr/bin/cp", "--archive", "--no-dereference", "--", radiusDirectory, filepath.Join(t.directory, "radius")); err != nil {
		return err
	}
	if _, err = execute(ctx, "/usr/bin/sync", "--file-system", t.directory); err != nil {
		return err
	}
	if manifest != nil {
		copied, err := nativeTreeManifest(filepath.Join(t.directory, "radius"))
		if err != nil || !bytes.Equal(copied, manifest) {
			return errors.New("native backup differs from original manifest")
		}
	}
	t.receipt.TreeSaved = true
	t.receipt.HadRadius = true
	return t.persist(t.receipt.Phase)
}
func (t *Transaction) restoreRadius(ctx context.Context) error {
	if !t.receipt.TreeSaved {
		return errors.New("original native configuration snapshot unavailable")
	}
	failed := filepath.Join(radiusParent, ".cloud8021x-failed-"+t.receipt.ID)
	if _, err := os.Lstat(radiusDirectory); err == nil {
		if err = os.Rename(radiusDirectory, failed); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if t.receipt.HadRadius {
		stage := filepath.Join(radiusParent, ".cloud8021x-restore-"+t.receipt.ID)
		if _, err := execute(ctx, "/usr/bin/cp", "--archive", "--no-dereference", "--", filepath.Join(t.directory, "radius"), stage); err != nil {
			return err
		}
		if _, err := execute(ctx, "/usr/bin/sync", "--file-system", stage); err != nil {
			return err
		}
		if err := os.Rename(stage, radiusDirectory); err != nil {
			return err
		}
	}
	_, err := execute(ctx, "/usr/bin/sync", "--file-system", radiusParent)
	return err
}

// InstallPackages journals the independently bound plan and old complete native
// config before invoking dpkg. A partial install remains tied to this receipt.
func (t *Transaction) InstallPackages(ctx context.Context, plan PackagePlan) error {
	if t == nil || t.receipt.Phase != "planning" {
		return errors.New("package transaction is not planning")
	}
	if _, err := os.Lstat(radiusDirectory); err == nil {
		uid, gid, err := identity("freerad")
		if err != nil {
			return err
		}
		if err = migrateLegacyDirectory(radiusParent, Accounts{NativeUID: uid, NativeGID: gid}, t.directory); err != nil {
			return err
		}
	}
	if err := t.snapshotRadius(ctx); err != nil {
		return err
	}
	current, err := installedPackages()
	if err != nil {
		return err
	}
	if len(current) != len(plan.Installed) {
		return errors.New("installed packages changed after preflight")
	}
	for name, a := range current {
		if !samePackage(a, plan.Installed[name]) {
			return errors.New("installed package identity changed after preflight")
		}
	}
	t.receipt.Packages = &plan
	if err = t.persist("packages-started"); err != nil {
		return err
	}
	if plan.Changed {
		if err = plan.install(ctx); err != nil {
			return err
		}
	}
	return t.persist("packages-installed")
}
