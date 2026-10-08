package sources

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"

	"golang.org/x/sys/unix"
)

var proofHash = regexp.MustCompile(`^[a-f0-9]{64}$`)

// ExpectedProofGeneration derives a retention/reconciliation reference from the
// original candidate and protected configuration. It does not authenticate or
// publish trust; expired original observations remain expired.
func ExpectedProofGeneration(cfg Config, candidates []domain.SourceCandidate, now time.Time) (string, error) {
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	rows, err := checkedCandidates(candidates, cfg, now, true)
	if err != nil {
		return "", err
	}
	plan, err := makePlan(cfg, rows)
	if err != nil {
		return "", err
	}
	return proofGeneration(plan), nil
}

func clientHash(id string) string { h := sha256.Sum256([]byte(id)); return hex.EncodeToString(h[:]) }
func proofGeneration(p Plan) string {
	b, _ := json.Marshal(p)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// All operations are descriptor relative. Production uses the fixed protected
// path and root UID; unprivileged tests use their own private temporary directory.
func proofDirectory(parent int, name string) (int, error) {
	fd, e := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, e
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || (int(st.Uid) != os.Geteuid() && st.Uid != 0) || st.Mode&0022 != 0 {
		_ = unix.Close(fd)
		return -1, errors.New("unsafe source proof directory")
	}
	return fd, nil
}
func (o *FileOperations) openProof() (int, error) {
	if !filepath.IsAbs(o.proofPath) || filepath.Clean(o.proofPath) != o.proofPath {
		return -1, errors.New("invalid source proof path")
	}
	fd, e := proofDirectory(unix.AT_FDCWD, "/")
	if e != nil {
		return -1, e
	}
	for _, part := range strings.Split(strings.TrimPrefix(o.proofPath, "/"), "/") {
		next, e := proofDirectory(fd, part)
		// Like network.ReadPublished, only unprivileged test paths may cross sticky /tmp.
		if e != nil && os.Geteuid() != 0 {
			next, e = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if e == nil {
				var st unix.Stat_t
				if unix.Fstat(next, &st) != nil || st.Uid != 0 || st.Mode&unix.S_ISVTX == 0 {
					_ = unix.Close(next)
					next = -1
					e = errors.New("unsafe source proof ancestry")
				}
			}
		}
		_ = unix.Close(fd)
		if e != nil {
			return -1, e
		}
		fd = next
	}
	return fd, nil
}
func proofNames(fd int) ([]os.DirEntry, error) {
	dup, e := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(dup), "proof")
	defer func() { _ = f.Close() }()
	entries, e := f.ReadDir(4097)
	if e != nil && !errors.Is(e, io.EOF) {
		return nil, e
	}
	if len(entries) > 4096 {
		return nil, errors.New("source proof directory exceeds bound")
	}
	return entries, nil
}
func proofChild(parent int, name string) (int, error) {
	if e := unix.Mkdirat(parent, name, 0755); e != nil && !errors.Is(e, unix.EEXIST) {
		return -1, e
	}
	return proofDirectory(parent, name)
}
func (o *FileOperations) stageProof(p Plan) (string, error) {
	generation := proofGeneration(p)
	root, e := o.openProof()
	if e != nil {
		return "", e
	}
	defer func() { _ = unix.Close(root) }()
	if existing, e := proofDirectory(root, generation); e == nil {
		_ = unix.Close(existing)
		return generation, o.verifyProof(p, generation)
	} else if !errors.Is(e, unix.ENOENT) {
		return "", e
	}
	entries, e := proofNames(root)
	if e != nil {
		return "", e
	}
	if len(entries) >= 4096 {
		return "", errors.New("source proof retention bound reached")
	}
	// An unguessable private staging directory cannot be selected by the native reader.
	staging := fmt.Sprintf(".stage-%s-%d", generation, time.Now().UnixNano())
	if e = unix.Mkdirat(root, staging, 0700); e != nil {
		return "", e
	}
	stage, e := proofDirectory(root, staging)
	if e != nil {
		return "", e
	}
	defer func() { _ = unix.Close(stage) }()
	for _, c := range p.Clients {
		if !proofHash.MatchString(c.ConfigSHA256) || c.ObservedAt <= 0 || c.MaxAgeSeconds < 1 || c.MaxAgeSeconds > 3600 {
			return "", errors.New("invalid protected source proof")
		}
		config, e := proofChild(stage, c.ConfigSHA256)
		if e != nil {
			return "", e
		}
		client, e := proofChild(config, clientHash(c.ClientID))
		if e != nil {
			_ = unix.Close(config)
			return "", e
		}
		for _, raw := range c.CIDRs {
			prefix, e := netip.ParsePrefix(raw)
			if e != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 || prefix.String() != raw {
				_ = unix.Close(client)
				_ = unix.Close(config)
				return "", errors.New("invalid proof IPv4")
			}
			fd, e := unix.Openat(client, prefix.Addr().String(), unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0444)
			if e == nil {
				ts := []unix.Timeval{unix.NsecToTimeval(c.ObservedAt * int64(time.Second)), unix.NsecToTimeval(c.ObservedAt * int64(time.Second))}
				e = unix.Futimes(fd, ts)
				if e == nil {
					e = unix.Fsync(fd)
				}
				_ = unix.Close(fd)
			}
			if e != nil {
				_ = unix.Close(client)
				_ = unix.Close(config)
				return "", e
			}
		}
		e = unix.Fchmod(client, 0555)
		if e == nil {
			e = unix.Fsync(client)
		}
		_ = unix.Close(client)
		if e == nil {
			e = unix.Fsync(config)
		}
		_ = unix.Close(config)
		if e != nil {
			return "", e
		}
	}
	configs, e := proofNames(stage)
	if e != nil {
		return "", e
	}
	for _, entry := range configs {
		fd, e := proofDirectory(stage, entry.Name())
		if e != nil {
			return "", e
		}
		e = unix.Fchmod(fd, 0555)
		if e == nil {
			e = unix.Fsync(fd)
		}
		_ = unix.Close(fd)
		if e != nil {
			return "", e
		}
	}
	if e = unix.Fchmod(stage, 0555); e == nil {
		e = unix.Fsync(stage)
	}
	if e != nil {
		return "", e
	}
	if e = unix.Renameat(root, staging, root, generation); e == nil {
		e = unix.Fsync(root)
	}
	if e != nil {
		return "", e
	}
	return generation, o.verifyProof(p, generation)
}

func (o *FileOperations) verifyProof(p Plan, generation string) error {
	if !proofHash.MatchString(generation) || generation != proofGeneration(p) {
		return errors.New("source proof generation differs")
	}
	root, e := o.openProof()
	if e != nil {
		return e
	}
	defer func() { _ = unix.Close(root) }()
	gen, e := proofDirectory(root, generation)
	if e != nil {
		return e
	}
	defer func() { _ = unix.Close(gen) }()
	want := map[string]map[string]map[string]int64{}
	for _, c := range p.Clients {
		if want[c.ConfigSHA256] == nil {
			want[c.ConfigSHA256] = map[string]map[string]int64{}
		}
		markers := map[string]int64{}
		for _, raw := range c.CIDRs {
			prefix, e := netip.ParsePrefix(raw)
			if e != nil {
				return e
			}
			markers[prefix.Addr().String()] = c.ObservedAt
		}
		want[c.ConfigSHA256][clientHash(c.ClientID)] = markers
	}
	configs, e := proofNames(gen)
	if e != nil {
		return e
	}
	if len(configs) != len(want) {
		return errors.New("source proof configuration count differs")
	}
	for _, entry := range configs {
		clients, ok := want[entry.Name()]
		if !ok {
			return errors.New("unexpected source proof configuration")
		}
		config, e := proofDirectory(gen, entry.Name())
		if e != nil {
			return e
		}
		err := func() error {
			defer func() { _ = unix.Close(config) }()
			names, e := proofNames(config)
			if e != nil {
				return e
			}
			if len(names) != len(clients) {
				return errors.New("source proof client count differs")
			}
			for _, name := range names {
				markers, ok := clients[name.Name()]
				if !ok {
					return errors.New("unexpected source proof client")
				}
				client, e := proofDirectory(config, name.Name())
				if e != nil {
					return e
				}
				err := func() error {
					defer func() { _ = unix.Close(client) }()
					files, e := proofNames(client)
					if e != nil {
						return e
					}
					if len(files) != len(markers) {
						return errors.New("source proof marker count differs")
					}
					for _, file := range files {
						observed, ok := markers[file.Name()]
						if !ok {
							return errors.New("unexpected source proof marker")
						}
						fd, e := unix.Openat(client, file.Name(), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
						if e != nil {
							return e
						}
						var sys unix.Stat_t
						if e = unix.Fstat(fd, &sys); e != nil {
							_ = unix.Close(fd)
							return e
						}
						f := os.NewFile(uintptr(fd), "marker")
						st, e := f.Stat()
						_ = f.Close()
						if e != nil {
							return e
						}
						if !st.Mode().IsRegular() || st.Size() != 0 || int(sys.Uid) != os.Geteuid() || sys.Nlink != 1 || st.Mode().Perm()&0022 != 0 || st.ModTime().Unix() != observed || st.ModTime().Nanosecond() != 0 {
							return errors.New("source proof marker differs")
						}
					}
					return nil
				}()
				if err != nil {
					return err
				}
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}
