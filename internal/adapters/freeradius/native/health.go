package native

import (
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type SpoolHealth struct {
	Files          int
	Bytes          int64
	OldestAge      time.Duration
	AvailableBytes uint64
}

// ObserveSpool never opens/parses accounting records. Task8 grants directory
// listing/stat through the separate metadata-only group; files stay 0600.
// Write/replay failures are separate native log/status counters, not inferred
// as successful delivery from an empty directory.
func ObserveSpool(directory string, now time.Time) (SpoolHealth, error) {
	var h SpoolHealth
	fd, e := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return h, e
	}
	f := os.NewFile(uintptr(fd), "spool-metadata")
	defer func() { _ = f.Close() }()
	entries, e := f.Readdirnames(4097)
	if e != nil && !errors.Is(e, io.EOF) {
		return h, e
	}
	if len(entries) > 4096 {
		return h, errors.New("spool file limit exceeded")
	}
	var fs unix.Statfs_t
	if e = unix.Fstatfs(fd, &fs); e != nil {
		return h, e
	}
	h.AvailableBytes = uint64(fs.Bavail) * uint64(fs.Bsize)
	for _, name := range entries {
		if !strings.HasPrefix(name, "detail") {
			continue
		}
		var st unix.Stat_t
		if unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil {
			return h, errors.New("spool changed during observation")
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&0777 != 0600 {
			return h, errors.New("unsafe accounting spool file")
		}
		h.Files++
		h.Bytes += st.Size
		age := now.Sub(time.Unix(st.Mtim.Sec, st.Mtim.Nsec))
		if age > h.OldestAge {
			h.OldestAge = age
		}
	}
	return h, nil
}
