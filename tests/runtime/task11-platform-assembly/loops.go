package main

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type backingIdentity struct{ Device, Inode uint64 }
type loopObservation struct {
	Occupied bool
	Backing  backingIdentity
}

func validateLoopAllocation(planned, free []string, observed map[string]loopObservation, owned map[backingIdentity]string) error {
	if len(planned) != 2 || planned[0] == planned[1] {
		return errors.New("exact distinct loop pair required")
	}
	for device, observation := range observed {
		if !observation.Occupied {
			continue
		}
		if _, ours := owned[observation.Backing]; ours && device != planned[0] && device != planned[1] {
			return errors.New("owned collector attached outside exposed pair")
		}
	}
	remaining := []string{}
	seen := map[string]bool{}
	for _, p := range planned {
		v, ok := observed[p]
		if !ok {
			return errors.New("planned loop observation absent")
		}
		if !v.Occupied {
			remaining = append(remaining, p)
			continue
		}
		owner, ok := owned[v.Backing]
		if !ok || seen[owner] {
			return errors.New("planned loop belongs to foreign or duplicated backing")
		}
		seen[owner] = true
	}
	sort.Slice(remaining, func(i, j int) bool {
		a, _ := strconv.Atoi(strings.TrimPrefix(remaining[i], "/dev/loop"))
		b, _ := strconv.Atoi(strings.TrimPrefix(remaining[j], "/dev/loop"))
		return a < b
	})
	if len(free) < len(remaining) {
		return errors.New("approved free loops missing")
	}
	for i, p := range remaining {
		if free[i] != p {
			return errors.New("kernel allocator could select an unexposed loop")
		}
	}
	return nil
}
func collectorIdentity(name string) (backingIdentity, bool, error) {
	p := rootFor(name) + "/var/lib/cloud-8021x-bootstrap/collector.ext4"
	if _, e := os.Lstat(p); os.IsNotExist(e) {
		return backingIdentity{}, false, nil
	}
	fd, e := parent(p, false)
	if e != nil {
		return backingIdentity{}, false, e
	}
	defer func() { _ = unix.Close(fd) }()
	leaf, e := unix.Openat(fd, filepath.Base(p), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return backingIdentity{}, false, e
	}
	defer func() { _ = unix.Close(leaf) }()
	var st unix.Stat_t
	if unix.Fstat(leaf, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Gid != 0 || st.Nlink != 1 || st.Mode&0777 != 0600 || st.Size != 512*MiB {
		return backingIdentity{}, false, errors.New("actual collector backing identity differs")
	}
	return backingIdentity{uint64(st.Dev), st.Ino}, true, checkParentBinding(fd, p)
}
func (o operation) auditLoops() error {
	owned := map[backingIdentity]string{}
	for _, name := range []string{"green-primary", "green-secondary"} {
		v, ok, e := collectorIdentity(name)
		if e != nil {
			return e
		}
		if ok {
			if _, duplicate := owned[v]; duplicate {
				return errors.New("shared collector backing refused")
			}
			owned[v] = name
		}
	}
	files, e := filepath.Glob("/sys/class/block/loop*")
	if e != nil {
		return e
	}
	observed := map[string]loopObservation{}
	free := []string{}
	for _, p := range files {
		if _, e := strconv.Atoi(strings.TrimPrefix(filepath.Base(p), "loop")); e != nil {
			continue
		}
		device := "/dev/" + filepath.Base(p)
		v, e := observeLoop(device)
		if e != nil {
			return e
		}
		observed[device] = v
		if !v.Occupied {
			free = append(free, device)
		}
	}
	sort.Slice(free, func(i, j int) bool {
		a, _ := strconv.Atoi(strings.TrimPrefix(free[i], "/dev/loop"))
		b, _ := strconv.Atoi(strings.TrimPrefix(free[j], "/dev/loop"))
		return a < b
	})
	if e = validateLoopAllocation(o.in.Plan.LoopDevices, free, observed, owned); e != nil {
		return e
	}
	remaining := false
	for _, p := range o.in.Plan.LoopDevices {
		if !observed[p].Occupied {
			remaining = true
		}
	}
	if remaining {
		b, e := o.r.call(o.ctx, "losetup", "--find")
		if e != nil || len(free) == 0 || strings.TrimSpace(string(b)) != free[0] {
			return errors.New("actual kernel first-free allocator differs")
		}
	}
	return nil
}
