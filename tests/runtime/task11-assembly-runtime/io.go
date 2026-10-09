package main

import (
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
	seed "github.com/CampusTech/cloud-8021x/tests/runtime/task11-assembly-seed/contract"
	"golang.org/x/sys/unix"
)

func digest(b []byte) string { return adoption.Digest(b) }
func openRegular(name string, limit int64) (*os.File, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name || limit < 1 {
		return nil, errors.New("absolute clean private input required")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(name, "/"), "/")
	for _, part := range parts[:len(parts)-1] {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if e != nil {
			return nil, errors.New("input ancestry unavailable or symbolic")
		}
		fd = next
	}
	defer func() { _ = unix.Close(fd) }()
	leaf, err := unix.Openat(fd, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if unix.Fstat(leaf, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&0022 != 0 || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || st.Size < 1 || st.Size > limit {
		_ = unix.Close(leaf)
		return nil, errors.New("input must be owned bounded single-link regular file")
	}
	return os.NewFile(uintptr(leaf), name), nil
}
func readPinned(name, want string, limit int64) ([]byte, error) {
	return readPinnedMode(name, want, limit, false)
}
func readPinnedMode(name, want string, limit int64, private bool) ([]byte, error) {
	if !seed.IsSHA(want) {
		return nil, errors.New("independent byte pin required")
	}
	f, err := openRegular(name, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if private {
		st, err := f.Stat()
		if err != nil || st.Mode().Perm() != 0600 {
			return nil, errors.New("private seed and plan require mode0600")
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit || digest(b) != want {
		return nil, errors.New("bounded exact input bytes differ")
	}
	return b, nil
}
func verifyLarge(name, want string, limit int64) error {
	if !seed.IsSHA(want) {
		return errors.New("artifact pin absent")
	}
	f, err := openRegular(name, limit)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil || n > limit || hex.EncodeToString(h.Sum(nil)) != want {
		return errors.New("artifact bytes differ")
	}
	return nil
}
func cleanApplication(raw []byte, revision string) error {
	b, err := buildinfo.Read(bytes.NewReader(raw))
	if err != nil {
		return errors.New("shipping Go build metadata unavailable")
	}
	settings := map[string]string{}
	for _, s := range b.Settings {
		settings[s.Key] = s.Value
	}
	if settings["GOOS"] != "linux" || settings["GOARCH"] != "arm64" || settings["vcs.revision"] != revision || settings["vcs.modified"] != "false" || b.Path != "github.com/CampusTech/cloud-8021x/cmd/cloud-8021x" {
		return errors.New("clean pinned shipping Linux ARM application required")
	}
	return nil
}
func loadAssembly(p plan) (output, error) {
	var empty output
	if err := p.validate(); err != nil {
		return empty, err
	}
	raw, err := readPrivatePinned(filepath.Join(p.OriginalDirectory, "assembly-input.json"), p.InputSHA256, 1<<20)
	if err != nil {
		return empty, err
	}
	var s seed.Input
	if domain.DecodeJSONStrict(raw, &s) != nil {
		return empty, errors.New("invalid assembly input")
	}
	if err = s.Validate(); err != nil {
		return empty, err
	}
	files := map[string][]byte{}
	total := 0
	for name, pin := range s.Files {
		b, err := readPrivatePinned(filepath.Join(p.OriginalDirectory, name), pin, 8<<20)
		if err != nil {
			return empty, err
		}
		total += len(b)
		if total > 32<<20 {
			return empty, errors.New("private seed aggregate exceeds32MiB")
		}
		files[name] = b
	}
	for _, b := range []binaryPin{p.Controller, p.Observer, p.Cloud} {
		if err = verifyLarge(b.Path, b.SHA256, 160<<20); err != nil {
			return empty, err
		}
	}
	app, err := readPinned(p.Application.Path, p.Application.SHA256, 160<<20)
	if err != nil {
		return empty, err
	}
	if err = cleanApplication(app, p.ApplicationSourceSHA); err != nil {
		return empty, err
	}
	raw, err = readPinned(filepath.Join(p.ArtifactDirectory, "package-manifest.json"), p.ManifestSHA256, 1<<20)
	if err != nil {
		return empty, err
	}
	var packaged struct {
		Schema          int             `json:"schema"`
		Architecture    string          `json:"architecture"`
		CollectorSHA256 string          `json:"collector_sha256"`
		Artifacts       []host.Artifact `json:"artifacts"`
	}
	if domain.DecodeJSONStrict(raw, &packaged) != nil {
		return empty, errors.New("invalid artifact manifest")
	}
	m := host.Manifest{Schema: packaged.Schema, Architecture: packaged.Architecture, CollectorSHA256: packaged.CollectorSHA256, Artifacts: packaged.Artifacts, PostgresCASHA256: s.PostgresCA.SHA256}
	if err = m.Validate("arm64"); err != nil {
		return empty, err
	}
	if len(m.Artifacts) != 62 {
		return empty, errors.New("reviewed exact62 package closure required")
	}
	for _, a := range m.Artifacts {
		if err = verifyLarge(filepath.Join(p.ArtifactDirectory, a.Name+"_"+a.Version+"_"+a.Architecture+".deb"), a.SHA256, 256<<20); err != nil {
			return empty, err
		}
	}
	return assemble(p, s, files, m)
}

type heldDirectory struct {
	fd, parent int
	name       string
	device     uint64
	inode      uint64
	private    bool
}
type candidateWriter struct {
	dirs     []heldDirectory
	relative map[string]int
	uid      uint32
}

func directoryIdentity(fd int) (uint64, uint64, error) {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		return 0, 0, errors.New("directory identity unavailable")
	}
	return uint64(st.Dev), st.Ino, nil
}
func (w *candidateWriter) close() {
	for i := len(w.dirs) - 1; i >= 0; i-- {
		_ = unix.Close(w.dirs[i].fd)
	}
}
func (w *candidateWriter) retain(fd, parent int, name string, private bool) error {
	if len(w.dirs) >= 256 {
		_ = unix.Close(fd)
		return errors.New("candidate directory limit exceeded")
	}
	dev, ino, err := directoryIdentity(fd)
	if err != nil {
		_ = unix.Close(fd)
		return err
	}
	w.dirs = append(w.dirs, heldDirectory{fd, parent, name, dev, ino, private})
	return w.check()
}
func (w *candidateWriter) check() error {
	for _, d := range w.dirs {
		var st unix.Stat_t
		if unix.Fstat(d.fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || (st.Uid != 0 && st.Uid != w.uid) || st.Mode&0022 != 0 || uint64(st.Dev) != d.device || st.Ino != d.inode {
			return errors.New("protected candidate directory changed")
		}
		if d.private && (st.Uid != w.uid || st.Mode&0777 != 0700) {
			return errors.New("private candidate directory permissions changed")
		}
		if d.parent >= 0 {
			var linked unix.Stat_t
			if unix.Fstatat(d.parent, d.name, &linked, unix.AT_SYMLINK_NOFOLLOW) != nil || linked.Mode&unix.S_IFMT != unix.S_IFDIR || uint64(linked.Dev) != d.device || linked.Ino != d.inode {
				return errors.New("candidate directory entry substituted")
			}
		}
	}
	return nil
}
func newCandidateWriter(root string) (*candidateWriter, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" || len(root) > 4096 {
		return nil, errors.New("absolute exclusive protected output required")
	}
	w := &candidateWriter{relative: map[string]int{}, uid: uint32(os.Geteuid())}
	ok := false
	defer func() {
		if !ok {
			w.close()
		}
	}()
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("output ancestry unavailable")
	}
	if err = w.retain(fd, -1, "", false); err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(root, "/"), "/")
	if len(parts) > 64 {
		return nil, errors.New("output ancestry too deep")
	}
	for _, part := range parts[:len(parts)-1] {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return nil, errors.New("output ancestry unavailable or symbolic")
		}
		if err = w.retain(next, fd, part, false); err != nil {
			return nil, err
		}
		fd = next
	}
	name := parts[len(parts)-1]
	if err = unix.Mkdirat(fd, name, 0700); err != nil {
		return nil, errors.New("exclusive candidate output unavailable")
	}
	next, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("created output unavailable")
	}
	if err = w.retain(next, fd, name, true); err != nil {
		return nil, err
	}
	w.relative[""] = next
	ok = true
	return w, nil
}
func (w *candidateWriter) directory(parts []string) (int, error) {
	if err := w.check(); err != nil {
		return 0, err
	}
	parent := w.relative[""]
	key := ""
	for _, name := range parts {
		key = filepath.Join(key, name)
		if fd, ok := w.relative[key]; ok {
			parent = fd
			continue
		}
		if err := unix.Mkdirat(parent, name, 0700); err != nil {
			return 0, errors.New("exclusive candidate child directory refused")
		}
		fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return 0, errors.New("candidate child unavailable")
		}
		if err = w.retain(fd, parent, name, true); err != nil {
			return 0, err
		}
		w.relative[key] = fd
		parent = fd
	}
	return parent, nil
}
func (w *candidateWriter) write(name string, data []byte) error {
	if filepath.IsAbs(name) || filepath.Clean(name) != name || name == "." || strings.HasPrefix(name, "../") || len(name) > 1024 {
		return errors.New("invalid relative candidate path")
	}
	parts := strings.Split(name, "/")
	if len(parts) > 32 {
		return errors.New("candidate path too deep")
	}
	fd, err := w.directory(parts[:len(parts)-1])
	if err != nil {
		return err
	}
	leaf, err := unix.Openat(fd, parts[len(parts)-1], unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errors.New("exclusive candidate file refused")
	}
	f := os.NewFile(uintptr(leaf), "private-candidate")
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return errors.New("candidate write incomplete")
	}
	if closeErr != nil {
		return errors.New("candidate close failed")
	}
	return w.check()
}
func writeCandidates(root string, o output) error {
	if len(o.Files) == 0 || len(o.Files) > 1024 {
		return errors.New("bounded nonempty candidate inventory required")
	}
	for name, c := range o.Files {
		if filepath.IsAbs(name) || filepath.Clean(name) != name || strings.HasPrefix(name, "../") || strings.Count(name, "/") < 2 || len(c.Data) == 0 || digest(c.Data) != c.SHA256 {
			return errors.New("invalid candidate file")
		}
	}
	w, err := newCandidateWriter(root)
	if err != nil {
		return err
	}
	defer w.close()
	// Retain descriptors through all writes; partial private output remains on failure.
	for name, c := range o.Files {
		if err = w.write("files/"+name, c.Data); err != nil {
			return err
		}
	}
	raw, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return err
	}
	return w.write("candidate-index.json", raw)
}
func readPrivatePinned(name, want string, limit int64) ([]byte, error) {
	return readPinnedMode(name, want, limit, true)
}
