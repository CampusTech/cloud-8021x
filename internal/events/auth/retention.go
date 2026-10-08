package auth

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type CursorBatch interface {
	AuthCursors(context.Context, []string) (map[string]string, error)
}
type RetentionResult struct{ Inspected, Removed, Retained int }

// PruneClosed is a root-only consumer of protected producer-generation evidence.
// The caller has already stopped native, proved process exit, and excluded both
// the new and rollback generations. Age and clock changes never confer closure.
func (r *Reader) PruneClosed(ctx context.Context, closed map[string]bool, store CursorBatch) (RetentionResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := RetentionResult{}
	if os.Geteuid() != 0 || store == nil {
		return out, errors.New("root closed-generation retention required")
	}
	fd, e := unix.Openat(int(r.directory.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return out, e
	}
	dir := os.NewFile(uintptr(fd), "auth")
	names, e := dir.Readdirnames(8193)
	_ = dir.Close()
	if (e != nil && !errors.Is(e, io.EOF)) || len(names) > 8192 {
		return out, errors.New("auth retention scan exceeds recovery bound")
	}
	sources := []string{}
	for _, name := range names {
		if filename.MatchString(name) && closed[strings.Split(name, "-")[1]] {
			sources = append(sources, r.options.Host+"/"+name)
		}
	}
	if len(sources) > 4096 {
		return out, errors.New("closed auth generation file bound exceeded")
	}
	cursors, e := store.AuthCursors(ctx, sources)
	if e != nil {
		return out, e
	}
	for _, source := range sources {
		if e = ctx.Err(); e != nil {
			return out, e
		}
		out.Inspected++
		name := strings.TrimPrefix(source, r.options.Host+"/")
		fd, e := unix.Openat(int(r.directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if e != nil {
			return out, e
		}
		var before, after, path unix.Stat_t
		valid := unix.Fstat(fd, &before) == nil && before.Mode&unix.S_IFMT == unix.S_IFREG && before.Nlink == 1 && int(before.Uid) == r.options.ProducerUID && int(before.Gid) == r.options.EventGID && before.Mode&0777 == 0640
		cursor, parse := strconv.ParseInt(cursors[source], 10, 64)
		if !valid || parse != nil || cursor != before.Size || cursor < 0 {
			_ = unix.Close(fd)
			out.Retained++
			continue
		}
		// Posix advisory lock also rejects an overlapping producer write. Closure is
		// independently required; a lock alone cannot rule out a future reopen.
		lock := unix.Flock_t{Type: unix.F_RDLCK, Whence: 0, Start: 0, Len: 0}
		e = unix.FcntlFlock(uintptr(fd), unix.F_SETLK, &lock)
		if e != nil {
			_ = unix.Close(fd)
			out.Retained++
			continue
		}
		valid = unix.Fstat(fd, &after) == nil && unix.Fstatat(int(r.directory.Fd()), name, &path, unix.AT_SYMLINK_NOFOLLOW) == nil && after.Dev == before.Dev && after.Ino == before.Ino && after.Size == before.Size && path.Dev == before.Dev && path.Ino == before.Ino && path.Size == before.Size && path.Nlink == 1
		if !valid {
			_ = unix.Close(fd)
			return out, errors.New("auth file changed during closed-generation cleanup")
		}
		e = unix.Unlinkat(int(r.directory.Fd()), name, 0)
		_ = unix.Close(fd)
		if e != nil {
			return out, e
		}
		out.Removed++
	}
	if out.Removed > 0 {
		if e = unix.Fsync(int(r.directory.Fd())); e != nil {
			return out, e
		}
	}
	return out, nil
}
