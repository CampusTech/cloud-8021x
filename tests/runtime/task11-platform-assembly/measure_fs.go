package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

func sameBaseStat(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func hashBaseFile(ctx context.Context, fd int, st unix.Stat_t, limit int64) (string, error) {
	f := os.NewFile(uintptr(fd), "measured-public-file")
	defer func() { _ = f.Close() }()
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Nlink < 1 || st.Mode&0022 != 0 || st.Size < 0 || st.Size > limit {
		return "", errors.New("public source identity or bound differs")
	}
	h := sha256.New()
	buffer := make([]byte, 1<<20)
	var count int64
	for {
		if ctx.Err() != nil {
			return "", errors.New("public source measurement cancelled")
		}
		n, err := f.Read(buffer)
		count += int64(n)
		if count > st.Size || count > limit {
			return "", errors.New("public source grew during measurement")
		}
		if n > 0 {
			_, _ = h.Write(buffer[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", errors.New("public source read failed")
		}
	}
	var after unix.Stat_t
	if count != st.Size || unix.Fstat(fd, &after) != nil || !sameBaseStat(st, after) {
		return "", errors.New("public source changed during measurement")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func measureBaseTool(ctx context.Context, p string) (string, error) {
	dir, err := parent(p, false)
	if err != nil {
		return "", err
	}
	defer func() { _ = unix.Close(dir) }()
	fd, err := unix.Openat(dir, path.Base(p), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", errors.New("canonical regular guest tool absent")
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Nlink != 1 || st.Mode&0111 == 0 {
		_ = unix.Close(fd)
		return "", errors.New("canonical executable tool identity differs")
	}
	h, err := hashBaseFile(ctx, fd, st, 160<<20)
	if err != nil {
		return "", err
	}
	if err = checkParentBinding(dir, p); err != nil {
		return "", err
	}
	var current unix.Stat_t
	if unix.Fstatat(dir, path.Base(p), &current, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameBaseStat(st, current) {
		return "", errors.New("guest tool substituted during measurement")
	}
	return h, nil
}

func openBaseDirectory(root int, logical string) (int, error) {
	fd, err := unix.Dup(root)
	if err != nil {
		return -1, err
	}
	for _, n := range strings.Split(strings.TrimPrefix(logical, "/"), "/") {
		if n == "" {
			continue
		}
		next, err := unix.Openat(fd, n, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if err != nil {
			return -1, errors.New("public source ancestry changed")
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0022 != 0 {
			_ = unix.Close(fd)
			return -1, errors.New("unsafe public source ancestry")
		}
	}
	return fd, nil
}
func recheckBaseDirectory(root, retained int, logical string) error {
	fd, err := openBaseDirectory(root, logical)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	var a, b unix.Stat_t
	if unix.Fstat(fd, &a) != nil || unix.Fstat(retained, &b) != nil || a.Dev != b.Dev || a.Ino != b.Ino || a.Mode != b.Mode || a.Uid != b.Uid {
		return errors.New("retained public source directory substituted")
	}
	return nil
}

func measureLowerAt(ctx context.Context, root, entryLimit int, byteLimit int64) (lowerManifest, error) {
	m := lowerManifest{Schema: 1}
	var total int64
	metadata := 64
	visited := 0
	if entryLimit < 1 || entryLimit > 200000 || byteLimit < 0 || byteLimit > 1664*MiB {
		return m, errors.New("public projection bounds differ")
	}
	appendEntry := func(e lowerEntry) error {
		if len(m.Entries) >= entryLimit {
			return errors.New("public projection entry bound exceeded")
		}
		b, err := json.Marshal(e)
		if err != nil {
			return err
		}
		metadata += len(b) + 1
		if metadata > 32<<20 {
			return errors.New("public projection metadata bound exceeded")
		}
		m.Entries = append(m.Entries, e)
		return nil
	}
	var visit func(int, string, string, int) error
	visit = func(parentFD int, name, logical string, depth int) error {
		if ctx.Err() != nil {
			return errors.New("public projection cancelled")
		}
		visited++
		if visited > 200000 || depth > 64 || len(logical) > 4096 || !utf8.ValidString(logical) {
			return errors.New("public projection traversal exceeds bound")
		}
		// Excluded identities are rejected by name before any stat/open/read.
		privatePostgres := logical == "/etc/postgresql" || strings.HasPrefix(logical, "/etc/postgresql/")
		if !allowedLower(logical) || strings.HasPrefix(logical, "/etc/shadow") || strings.HasPrefix(logical, "/etc/gshadow") || privatePostgres {
			return nil
		}
		var st unix.Stat_t
		if err := unix.Fstatat(parentFD, name, &st, unix.AT_SYMLINK_NOFOLLOW); err == unix.ENOENT && depth == 0 {
			return nil
		} else if err != nil {
			return errors.New("public projection leaf unavailable")
		}
		e := lowerEntry{Path: logical, Mode: uint32(st.Mode) & 07777}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFREG:
			fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if err != nil {
				return errors.New("public projection leaf substituted")
			}
			var opened unix.Stat_t
			if unix.Fstat(fd, &opened) != nil || !sameBaseStat(st, opened) {
				_ = unix.Close(fd)
				return errors.New("public projection leaf substituted")
			}
			h, err := hashBaseFile(ctx, fd, st, byteLimit-total)
			if err != nil {
				return err
			}
			e.Kind = "file"
			e.Bytes = st.Size
			e.SHA256 = h
			total += st.Size
		case unix.S_IFLNK:
			if st.Uid != uint32(os.Geteuid()) {
				return errors.New("public link owner differs")
			}
			buf := make([]byte, 4097)
			n, err := unix.Readlinkat(parentFD, name, buf)
			if err != nil || n == 0 || n > 4096 {
				return errors.New("public link target exceeds bound")
			}
			target := string(buf[:n])
			resolved := target
			if !path.IsAbs(resolved) {
				resolved = path.Join(path.Dir(logical), resolved)
			}
			if !allowedLower(path.Clean(resolved)) {
				return nil
			}
			if !utf8.ValidString(target) {
				return errors.New("public link target invalid")
			}
			e.Kind = "symlink"
			e.Target = target
		case unix.S_IFDIR:
			if st.Uid != uint32(os.Geteuid()) || st.Mode&0022 != 0 {
				return errors.New("unsafe public directory")
			}
			e.Kind = "directory"
			if err := appendEntry(e); err != nil {
				return err
			}
			fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				return errors.New("public directory unavailable")
			}
			d := os.NewFile(uintptr(fd), "measured-public-directory")
			defer func() { _ = d.Close() }()
			var opened unix.Stat_t
			if unix.Fstat(fd, &opened) != nil || !sameBaseStat(st, opened) {
				return errors.New("public directory substituted")
			}
			for {
				names, err := d.Readdirnames(256)
				for _, n := range names {
					if n == "" || n == "." || n == ".." || strings.Contains(n, "/") {
						return errors.New("invalid public directory member")
					}
					if err := visit(fd, n, path.Join(logical, n), depth+1); err != nil {
						return err
					}
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					return errors.New("public directory read failed")
				}
			}
			return recheckBaseDirectory(root, fd, logical)
		default:
			// Devices, FIFOs and sockets are never opened or read.
			return nil
		}
		var current unix.Stat_t
		if unix.Fstatat(parentFD, name, &current, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameBaseStat(st, current) {
			return errors.New("public projection leaf changed")
		}
		return appendEntry(e)
	}
	for _, p := range []string{"/usr", "/etc", "/var", "/bin", "/sbin", "/lib", "/lib64"} {
		if err := visit(root, strings.TrimPrefix(p, "/"), p, 0); err != nil {
			return lowerManifest{}, err
		}
	}
	sort.Slice(m.Entries, func(i, j int) bool { return m.Entries[i].Path < m.Entries[j].Path })
	if err := m.validate(); err != nil {
		return lowerManifest{}, err
	}
	return m, nil
}
