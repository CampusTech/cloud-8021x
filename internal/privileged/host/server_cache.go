package host

import (
	"errors"
	"io"
	"os"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/adapters/stepca"
	"golang.org/x/sys/unix"
)

// ReadNativeServerCache only reads the two fixed legacy/native leaf paths. It
// permits the known freerad owner inside the native tree before migration, pins
// every descriptor, and distinguishes genuine absence from any unsafe/read state.
func ReadNativeServerCache() (stepca.ServerCertificate, error) {
	var result stepca.ServerCertificate
	uid, gid, err := identity("freerad")
	if err != nil {
		uid, gid = -1, -1
	}
	for _, key := range []bool{false, true} {
		leaf := "server-cert.pem"
		if key {
			leaf = "server-key.pem"
		}
		path := radiusDirectory + "/certs/" + leaf
		fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return result, e
		}
		prefix := ""
		missing := false
		for _, part := range strings.Split(strings.TrimPrefix(radiusDirectory+"/certs", "/"), "/") {
			prefix += "/" + part
			next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			_ = unix.Close(fd)
			if errors.Is(e, unix.ENOENT) {
				missing = true
				break
			}
			if e != nil {
				return result, errors.New("installed server cache ancestry unreadable")
			}
			fd = next
			var st unix.Stat_t
			if unix.Fstat(fd, &st) != nil || st.Mode&0022 != 0 || (st.Uid != 0 && (int(st.Uid) != uid || (prefix != radiusParent && !strings.HasPrefix(prefix, radiusParent+"/")))) {
				_ = unix.Close(fd)
				return result, errors.New("installed server cache ancestry rejected")
			}
		}
		if missing {
			continue
		}
		file, e := unix.Openat(fd, leaf, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if errors.Is(e, unix.ENOENT) {
			continue
		}
		if e != nil {
			return result, errors.New("installed server cache unreadable")
		}
		f := os.NewFile(uintptr(file), path)
		var st unix.Stat_t
		unsafe := unix.Fstat(file, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&0022 != 0 || (st.Uid != 0 && int(st.Uid) != uid) || st.Size <= 0 || st.Size > 1<<20
		if key {
			unsafe = unsafe || st.Mode&0007 != 0 || (st.Mode&0040 != 0 && int(st.Gid) != gid)
		}
		if unsafe {
			_ = f.Close()
			return result, errors.New("installed server certificate/key ownership or mode rejected")
		}
		data, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
		_ = f.Close()
		if e != nil || len(data) > 1<<20 {
			return result, errors.New("installed server cache read failed")
		}
		if key {
			result.Key = data
		} else {
			result.Certificate = data
		}
	}
	if (len(result.Certificate) == 0) != (len(result.Key) == 0) {
		return result, errors.New("partial installed server cache requires recovery")
	}
	return result, nil
}
