//go:build linux

package main

import (
	"errors"

	"golang.org/x/sys/unix"
)

func observeLoop(path string) (loopObservation, error) {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return loopObservation{}, e
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFBLK || st.Uid != 0 || unix.Major(uint64(st.Rdev)) != 7 {
		return loopObservation{}, errors.New("actual loop block identity differs")
	}
	v, e := unix.IoctlLoopGetStatus64(fd)
	if e == unix.ENXIO {
		return loopObservation{}, nil
	}
	if e != nil {
		return loopObservation{}, e
	}
	return loopObservation{Occupied: true, Backing: backingIdentity{v.Device, v.Inode}}, nil
}
