package host

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/adapters/stepca"

	"golang.org/x/sys/unix"
)

var fixedFiles = map[string]bool{
	legacyPolicySnapshot: true, daemonPolicySnapshot: true,
	"/etc/cloud-8021x/sources/clients.conf": true,
	transactionRoot + "/current.json":       true,
	legacyClassKey:                          true, "/etc/systemd/system/freeradius.service.d/accounting-key.conf": true,
	credentialCachePath:               true,
	"/etc/datadog-agent/datadog.yaml": true, "/etc/datadog-agent/conf.d/freeradius.d/conf.yaml": true, "/etc/systemd/system/datadog-agent-ddot.service": true, "/etc/systemd/system/datadog-agent.service.d/cloud-8021x.conf": true, "/etc/systemd/system/var-lib-cloud8021x-collector.mount": true,
	"/usr/local/bin/cloud-8021x": true, "/etc/cloud-8021x/config.yaml": true,
	"/etc/acme-authz-webhook/server.crt": true, "/etc/acme-authz-webhook/server.key": true,
	"/etc/cloud-8021x/ec-intermediate.pem": true, "/etc/cloud-8021x/rsa-intermediate.pem": true,
	"/etc/systemd/system/cloud-8021x-credentials.service": true, "/etc/systemd/system/cloud-8021x-metadata.service": true,
	"/usr/sbin/policy-rc.d":         true,
	"/etc/cloud-8021x/metadata.nft": true, "/etc/cloud-8021x/ddot.yaml": true, "/etc/cloud-8021x/radius-server.pem": true, "/etc/cloud-8021x/client-cas.pem": true,
	"/etc/sudoers.d/cloud-8021x": true, "/etc/tmpfiles.d/cloud-8021x.conf": true, "/etc/systemd/system/cloud-8021x.service": true, "/etc/systemd/system/cloud-8021x-bootstrap.service": true, "/etc/systemd/system/cloud-8021x-renew.service": true, "/etc/systemd/system/cloud-8021x-renew.timer": true, "/etc/systemd/system/cloud-8021x-sources.service": true, "/etc/systemd/system/cloud-8021x-sources.timer": true, "/etc/systemd/system/step-ca.service": true, "/etc/systemd/system/step-ca-rsa.service": true, "/etc/systemd/system/freeradius.service.d/cloud-8021x.conf": true,
	"/usr/local/share/ca-certificates/acme-webhook.crt": true, "/etc/cloud-8021x/webhook.crt": true, "/run/cloud-8021x/credentials/webhook.key": true, "/etc/freeradius/3.0/certs/server-cert.pem": true, "/etc/freeradius/3.0/certs/server-key.pem": true,
}

func AllowedFile(path string) bool {
	if filepath.Clean(path) != path {
		return false
	}
	if fixedFiles[path] || legacyWriterFile(path) {
		return true
	}
	for _, base := range []string{"/etc/step-ca", "/etc/step-ca-rsa"} {
		for _, leaf := range []string{"certs/root_ca.crt", "certs/intermediate_ca.crt", "certs/scep_decrypter.crt", "secrets/scep_decrypter_key", "config/ca.json", "templates/x509/wifi-acme.tpl", "templates/x509/wifi-scep.tpl"} {
			if path == base+"/"+leaf {
				return true
			}
		}
	}
	for _, leaf := range []string{"radiusd.conf", "dictionary", "clients.conf", "mods-enabled/eap", "mods-enabled/rest", "mods-enabled/sql", "mods-enabled/accounting_detail", "mods-enabled/auth_detail", "mods-enabled/always", "sites-enabled/default", "sites-enabled/certificate", "sites-enabled/buffered", "sites-enabled/health"} {
		if path == "/etc/freeradius/3.0/"+leaf {
			return true
		}
	}
	parent := filepath.Dir(path)
	return (parent == "/run/cloud-8021x/credentials" || parent == "/run/cloud-8021x-root" || parent == "/run/cloud-8021x-collector") && regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`).MatchString(filepath.Base(path))
}

type File struct {
	restoring      bool
	replacementUID int
	adoptUID       int
	Path           string
	Data           []byte
	UID, GID       int
	Mode           uint32
}
type SavedFile struct {
	ReplacementUID int `json:"replacement_uid"`
	File
	Exists bool
}

// parentDescriptor pins every ancestor before any leaf operation. It never
// traverses a symlink and only permits a nonroot owner on a final credential dir.
func parentDescriptor(path string, owner int, create bool) (int, error) {
	if !AllowedFile(path) {
		return -1, errors.New("unapproved installed file")
	}
	fd, e := unix.Open("/", unix.O_DIRECTORY|unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, e
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/")
	for i, part := range parts {
		if create {
			e = unix.Mkdirat(fd, part, 0755)
			if e != nil && !errors.Is(e, unix.EEXIST) {
				_ = unix.Close(fd)
				return -1, e
			}
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if e != nil {
			return -1, errors.New("unsafe installed directory")
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Mode&0022 != 0 || (st.Uid != 0 && (i != len(parts)-1 || int(st.Uid) != owner)) {
			_ = unix.Close(fd)
			return -1, errors.New("unsafe installed directory owner or mode")
		}
	}
	return fd, nil
}
func Snapshot(file File) (SavedFile, error) {
	saved := SavedFile{File: file, ReplacementUID: file.UID}
	saved.Data = nil
	dir, e := parentDescriptor(file.Path, file.UID, false)
	if e != nil {
		return saved, e
	}
	defer func() { _ = unix.Close(dir) }()
	fd, e := unix.Openat(dir, filepath.Base(file.Path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(e, unix.ENOENT) {
		return saved, nil
	}
	if e != nil {
		return saved, errors.New("installed file unavailable")
	}
	f := os.NewFile(uintptr(fd), "protected-installed-input")
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&0022 != 0 || !file.acceptsOwner(int(st.Uid)) {
		return saved, errors.New("unsafe installed file")
	}
	limit := int64(16 << 20)
	if file.Path == "/usr/local/bin/cloud-8021x" {
		limit = 256 << 20
	}
	data, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(data)) > limit {
		return saved, errors.New("installed file read exceeds bound")
	}
	saved.Data = data
	saved.UID = int(st.Uid)
	saved.GID = int(st.Gid)
	saved.Mode = uint32(st.Mode) & 0777
	saved.Exists = true
	return saved, nil
}

// Write stages on the destination filesystem, fsyncs, chowns, then atomically
// replaces. Existing root/app-owned regular single-link files alone are adopted.
func Write(file File) error {
	if os.Geteuid() != 0 || file.UID < 0 || file.GID < 0 || (file.Mode != 0600 && file.Mode != 0644 && file.Mode != 0640 && file.Mode != 0440 && ((file.Path != "/usr/sbin/policy-rc.d" && file.Path != "/usr/local/bin/cloud-8021x" && !slices.Contains(legacyWriterHelpers, file.Path)) || file.Mode != 0755) && (!file.restoring || file.Mode > 0777 || file.Mode&0022 != 0)) || len(file.Data) > 256<<20 {
		return errors.New("invalid protected file operation")
	}
	parentOwner := file.UID
	if file.restoring {
		parentOwner = file.replacementUID
	}
	dir, e := parentDescriptor(file.Path, parentOwner, true)
	if e != nil {
		return e
	}
	defer func() { _ = unix.Close(dir) }()
	var st unix.Stat_t
	e = unix.Fstatat(dir, filepath.Base(file.Path), &st, unix.AT_SYMLINK_NOFOLLOW)
	if e == nil && (st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&0022 != 0 || !file.acceptsOwner(int(st.Uid))) {
		return errors.New("unsafe existing installed file")
	}
	if e != nil && !errors.Is(e, unix.ENOENT) {
		return e
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return e
	}
	name := ".cloud8021x-" + hex.EncodeToString(nonce[:])
	fd, e := unix.Openat(dir, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), "protected-installed-output")
	defer func() { _ = unix.Unlinkat(dir, name, 0) }()
	_, e = f.Write(file.Data)
	if e == nil {
		e = f.Chown(file.UID, file.GID)
	}
	if e == nil {
		e = f.Chmod(os.FileMode(file.Mode))
	}
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return errors.New("installed file staging failed")
	}
	if e = unix.Renameat(dir, name, dir, filepath.Base(file.Path)); e != nil {
		return errors.New("installed file rename failed")
	}
	return unix.Fsync(dir)
}
func Restore(saved SavedFile) error {
	if saved.Exists {
		saved.restoring = true
		saved.replacementUID = saved.ReplacementUID
		return Write(saved.File)
	}
	dir, e := parentDescriptor(saved.Path, saved.UID, false)
	if e != nil {
		return e
	}
	defer func() { _ = unix.Close(dir) }()
	var st unix.Stat_t
	e = unix.Fstatat(dir, filepath.Base(saved.Path), &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(e, unix.ENOENT) {
		return nil
	}
	if e != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || (st.Uid != 0 && int(st.Uid) != saved.UID) {
		return errors.New("unsafe installed rollback target")
	}
	if e = unix.Unlinkat(dir, filepath.Base(saved.Path), 0); e != nil {
		return e
	}
	return unix.Fsync(dir)
}

// PrepareFileDirectories creates only allowlisted parents. Secret CA directories
// remain root-private, while runtime credential ownership was established by
// PrepareDirectories before entering this stage.
func PrepareFileDirectories(files []File) error {
	for _, file := range files {
		if !AllowedFile(file.Path) {
			return errors.New("unapproved installation file")
		}
		parent := filepath.Dir(file.Path)
		if strings.HasPrefix(parent, "/run/") {
			continue
		}
		mode := uint32(0755)
		if strings.HasPrefix(parent, "/etc/step-ca") || parent == transactionRoot || parent == "/etc/cloud-8021x/sources" {
			mode = 0700
		}
		if e := protectedDirectory(parent, 0, 0, mode); e != nil {
			return e
		}
	}
	return nil
}

// ReadWebhookCache reads only the preserved legacy fixed identity. Missing both
// files means initial setup; a partial pair or any unsafe/read-error fails closed.
func ReadWebhookCache() (stepca.ServerCertificate, error) {
	var result stepca.ServerCertificate
	for path, target := range map[string]*[]byte{"/etc/acme-authz-webhook/server.crt": &result.Certificate, "/etc/acme-authz-webhook/server.key": &result.Key} {
		f, e := rootFile(path, 1<<20)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return result, errors.New("protected webhook cache unreadable")
		}
		if target == &result.Key {
			st, err := f.Stat()
			if err != nil || st.Mode().Perm()&0077 != 0 {
				_ = f.Close()
				return result, errors.New("webhook private key permissions rejected")
			}
		}
		*target, e = io.ReadAll(f)
		_ = f.Close()
		if e != nil {
			return result, errors.New("protected webhook cache unreadable")
		}
	}
	if (len(result.Certificate) == 0) != (len(result.Key) == 0) {
		return result, errors.New("partial webhook TLS cache requires explicit recovery")
	}
	return result, nil
}

func ReadClientTrust() ([]byte, error) {
	f, e := rootFile("/etc/cloud-8021x/client-cas.pem", 1<<20)
	if e != nil {
		return nil, errors.New("installed client trust unavailable")
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}

func (f File) acceptsOwner(uid int) bool {
	if uid == 0 || uid == f.UID || (f.restoring && uid == f.replacementUID) {
		return true
	}
	return f.adoptUID > 0 && uid == f.adoptUID && (f.Path == "/etc/datadog-agent/datadog.yaml" || f.Path == "/etc/datadog-agent/conf.d/freeradius.d/conf.yaml" || f.Path == legacyClassKey || f.Path == legacyVLANModule)
}

// BootstrapDiscoveryFiles initializes only the fixed missing discovery include.
func BootstrapDiscoveryFiles(enabled bool) ([]File, error) {
	if !enabled {
		return nil, nil
	}
	include := File{Path: "/etc/cloud-8021x/sources/clients.conf", Data: []byte("# No source candidates have been applied.\n"), Mode: 0600}
	if err := PrepareFileDirectories([]File{include}); err != nil {
		return nil, err
	}
	old, err := Snapshot(include)
	if err != nil {
		return nil, err
	}
	if old.Exists {
		return nil, nil
	}
	return []File{include}, nil
}
