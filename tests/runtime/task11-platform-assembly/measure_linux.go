//go:build linux

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func measureBaseLoops(ctx context.Context) ([]baseLoopFact, error) {
	fd, err := parent("/sys/class/block/.measure", false)
	if err != nil {
		return nil, errors.New("existing kernel block observations unavailable")
	}
	d := os.NewFile(uintptr(fd), "kernel-block-names")
	defer func() { _ = d.Close() }()
	var facts []baseLoopFact
	count := 0
	for {
		names, err := d.Readdirnames(256)
		count += len(names)
		if count > 4096 {
			return nil, errors.New("kernel block observations exceed bound")
		}
		for _, n := range names {
			if ctx.Err() != nil {
				return nil, errors.New("kernel observations cancelled")
			}
			if !strings.HasPrefix(n, "loop") {
				continue
			}
			minor, err := strconv.Atoi(strings.TrimPrefix(n, "loop"))
			if err != nil || minor < 0 || minor > 999 || n != "loop"+strconv.Itoa(minor) {
				return nil, errors.New("kernel loop name outside closed bound")
			}
			p := "/dev/" + n
			parentFD, err := parent(p, false)
			if err != nil {
				return nil, err
			}
			leaf, err := unix.Openat(parentFD, n, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if err != nil {
				_ = unix.Close(parentFD)
				return nil, errors.New("existing loop node unavailable")
			}
			var st unix.Stat_t
			if unix.Fstat(leaf, &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFBLK || unix.Major(uint64(st.Rdev)) != 7 || unix.Minor(uint64(st.Rdev)) != uint32(minor) {
				_ = unix.Close(leaf)
				_ = unix.Close(parentFD)
				return nil, errors.New("actual loop major/minor identity differs")
			}
			v := baseLoopFact{Path: p, Major: 7, Minor: uint32(minor)}
			info, queryErr := unix.IoctlLoopGetStatus64(leaf)
			_ = unix.Close(leaf)
			var current unix.Stat_t
			bindingErr := checkParentBinding(parentFD, p)
			statErr := unix.Fstatat(parentFD, n, &current, unix.AT_SYMLINK_NOFOLLOW)
			_ = unix.Close(parentFD)
			if bindingErr != nil || statErr != nil || !sameBaseStat(st, current) {
				return nil, errors.New("loop node substituted during observation")
			}
			if queryErr == nil {
				v.Occupied = true
				v.Backing = backingIdentity{info.Device, info.Inode}
			} else if !errors.Is(queryErr, unix.ENXIO) {
				return nil, errors.New("actual loop occupancy unavailable")
			}
			facts = append(facts, v)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("kernel block observation read failed")
		}
	}
	sort.Slice(facts, func(i, j int) bool { return facts[i].Minor < facts[j].Minor })
	return facts, nil
}
