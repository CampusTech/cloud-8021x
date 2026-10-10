package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const nativeELFSHA256 = "b6b68a52dc15c9797ca8bc32645f51e4e758149158cea6522b3417660d437036"

func openNativeELFAt(path, pin string, uid int) (*os.File, error) {
	refuse := errors.New("retained pinned ARM native executable unavailable")
	if uid < 0 || !shaPattern.MatchString(pin) {
		return nil, refuse
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, refuse
	}
	file := os.NewFile(uintptr(fd), "fixed-native-eapol")
	bad := func() (*os.File, error) { _ = file.Close(); return nil, refuse }
	var before, after unix.Stat_t
	valid := func(s unix.Stat_t) bool {
		return int(s.Uid) == uid && s.Mode&unix.S_IFMT == unix.S_IFREG && s.Mode&07777 == 0755 && s.Nlink == 1 && s.Size >= 64 && s.Size <= 4<<20
	}
	if unix.Fstat(fd, &before) != nil || !valid(before) {
		return bad()
	}
	var header [64]byte
	if _, e = io.ReadFull(file, header[:]); e != nil || string(header[:4]) != "\x7fELF" || header[4] != 2 || header[5] != 1 || header[6] != 1 || (binary.LittleEndian.Uint16(header[16:18]) != 2 && binary.LittleEndian.Uint16(header[16:18]) != 3) || binary.LittleEndian.Uint16(header[18:20]) != 183 {
		return bad()
	}
	if _, e = file.Seek(0, io.SeekStart); e != nil {
		return bad()
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(file, (4<<20)+1))
	if e != nil || n != before.Size || hex.EncodeToString(h.Sum(nil)) != pin || unix.Fstat(fd, &after) != nil || !valid(after) || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size {
		return bad()
	}
	if _, e = file.Seek(0, io.SeekStart); e != nil {
		return bad()
	}
	return file, nil
}
