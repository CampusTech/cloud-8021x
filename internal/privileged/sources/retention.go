package sources

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// PrepareRetention runs inside the installed helper's existing private apply.lock
// and shared maintenance gate. The protected caller supplies references derived
// from all unresolved persisted work; unknown/malformed evidence prevents cleanup.
// Incomplete .stage directories are retained for explicit reconciliation.
func (o *FileOperations) PrepareRetention(ctx context.Context) error {
	if o.RetainedProofs == nil {
		return nil
	}
	references, err := o.RetainedProofs(ctx)
	if err != nil {
		return errors.New("unresolved source references unavailable; proof cleanup withheld")
	}
	if len(references) > 1024 {
		return errors.New("unresolved proof retention exceeds bound")
	}
	keep := map[string]bool{}
	for _, reference := range references {
		if !proofHash.MatchString(reference) {
			return errors.New("invalid unresolved proof reference")
		}
		keep[reference] = true
	}
	for _, pointer := range []string{"current", "previous"} {
		data, present, err := readOptional(filepath.Join(o.proofPath, pointer), true)
		if err != nil {
			return err
		}
		if present {
			if !proofHash.Match(data) {
				return errors.New("invalid retained source pointer")
			}
			keep[string(data)] = true
		}
	}
	root, err := o.openProof()
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(root) }()
	entries, err := proofNames(root)
	if err != nil {
		return err
	}
	var remove []string
	for _, entry := range entries {
		if !proofHash.MatchString(entry.Name()) || keep[entry.Name()] {
			continue
		}
		fd, err := proofDirectory(root, entry.Name())
		if err != nil {
			return err
		}
		count := 0
		err = visitProofTree(fd, 0, false, &count)
		_ = unix.Close(fd)
		if err != nil {
			return err
		}
		remove = append(remove, entry.Name())
	}
	for _, name := range remove {
		if err := ctx.Err(); err != nil {
			return err
		}
		fd, err := proofDirectory(root, name)
		if err != nil {
			return err
		}
		count := 0
		err = visitProofTree(fd, 0, true, &count)
		_ = unix.Close(fd)
		if err != nil {
			return err
		}
		if err = unix.Unlinkat(root, name, unix.AT_REMOVEDIR); err != nil {
			return err
		}
	}
	return unix.Fsync(root)
}
func visitProofTree(fd, depth int, remove bool, count *int) error {
	if remove {
		if err := unix.Fchmod(fd, 0700); err != nil {
			return err
		}
	}
	names, err := proofNames(fd)
	if err != nil {
		return err
	}
	for _, entry := range names {
		*count++
		if *count > 8192 {
			return errors.New("proof tree exceeds retention bound")
		}
		if depth < 2 {
			if !proofHash.MatchString(entry.Name()) {
				return errors.New("invalid retained proof directory")
			}
			child, err := proofDirectory(fd, entry.Name())
			if err != nil {
				return err
			}
			err = visitProofTree(child, depth+1, remove, count)
			_ = unix.Close(child)
			if err != nil {
				return err
			}
			if remove {
				if err = unix.Unlinkat(fd, entry.Name(), unix.AT_REMOVEDIR); err != nil {
					return err
				}
			}
		} else {
			address, err := netip.ParseAddr(entry.Name())
			if err != nil || !address.Is4() {
				return errors.New("invalid retained proof marker")
			}
			var st unix.Stat_t
			if unix.Fstatat(fd, entry.Name(), &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != os.Geteuid() || st.Mode&0022 != 0 || st.Nlink != 1 || st.Size != 0 {
				return errors.New("unsafe retained proof marker")
			}
			if remove {
				if err = unix.Unlinkat(fd, entry.Name(), 0); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
