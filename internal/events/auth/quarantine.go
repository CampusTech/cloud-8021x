package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

type MalformedRange struct {
	Source, Expected, SHA256 string
	Start, End, FileSize     int64
	Device, Inode            uint64
	Data                     []byte
}

func ValidateMalformedRange(data []byte) error {
	if len(data) > 1<<20 || len(data) < 2 || bytes.Index(data, []byte("\n\n")) != len(data)-2 {
		return errors.New("exact single bounded complete record required")
	}
	record, n, e := Parse(data)
	if e != nil {
		return nil
	}
	if n != len(data) {
		return errors.New("incomplete auth range")
	}
	receipts := record.Values["C8021X-Receipt"]
	if len(receipts) != 1 {
		return nil
	}
	original, e := strconv.ParseInt(receipts[0], 10, 64)
	if e != nil || original <= 0 {
		return nil
	}
	return errors.New("valid native auth record cannot be quarantined")
}

// InspectMalformed never advances a cursor or alters native bytes. Root must
// first prove native stopped, and persist these exact bytes with the cursor CAS.
func (r *Reader) InspectMalformed(ctx context.Context, name string, offset int64, want string) (MalformedRange, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := MalformedRange{Source: r.options.Host + "/" + name, Start: offset, SHA256: want}
	if os.Geteuid() != 0 || !filename.MatchString(name) || offset < 0 || (want != "" && len(want) != 64) {
		return out, errors.New("root exact malformed auth range required")
	}
	fd, e := unix.Openat(int(r.directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return out, e
	}
	f := os.NewFile(uintptr(fd), name)
	defer func() { _ = f.Close() }()
	var before, after, path unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || int(before.Uid) != r.options.ProducerUID || int(before.Gid) != r.options.EventGID || before.Mode&0777 != 0640 {
		return out, errors.New("unsafe malformed auth file")
	}
	data := make([]byte, (1<<20)+1)
	n, e := f.ReadAt(data, offset)
	if e != nil && !errors.Is(e, io.EOF) {
		return out, e
	}
	data = data[:n]
	end := bytes.Index(data, []byte("\n\n"))
	if end < 0 {
		return out, errors.New("malformed complete boundary unavailable")
	}
	data = data[:end+2]
	if e = ValidateMalformedRange(data); e != nil {
		return out, e
	}
	digest := sha256.Sum256(data)
	if want != "" && hex.EncodeToString(digest[:]) != want {
		return out, errors.New("original malformed range digest differs")
	}
	if unix.Fstat(fd, &after) != nil || unix.Fstatat(int(r.directory.Fd()), name, &path, unix.AT_SYMLINK_NOFOLLOW) != nil || before.Ino != after.Ino || before.Size != after.Size || before.Dev != path.Dev || before.Ino != path.Ino || before.Size != path.Size {
		return out, errors.New("malformed file changed during inspection")
	}
	out.SHA256 = hex.EncodeToString(digest[:])
	out.Expected, e = r.options.Store.Cursor(ctx, out.Source)
	if e != nil {
		return out, e
	}
	current := int64(0)
	if out.Expected != "" {
		current, e = strconv.ParseInt(out.Expected, 10, 64)
		if e != nil {
			return out, e
		}
	}
	out.End = offset + int64(len(data))
	out.Device = uint64(before.Dev)
	out.Inode = before.Ino
	out.FileSize = before.Size
	out.Data = bytes.Clone(data)
	if current != offset && current < out.End {
		return out, errors.New("malformed range is not exact current or already-committed cursor")
	}
	return out, nil
}
