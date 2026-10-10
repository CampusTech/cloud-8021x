// Package identity owns the private, one-use TLS leaf handoff. No public constructor
// accepts a fingerprint or accounting Class as a verified certificate.
package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"golang.org/x/sys/unix"
)

const MaxLeafBytes = 1 << 20
const MaxHandoffBytes = 1024
const MaxHandoffAge = 120 * time.Second

var tokenPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var serialPattern = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)

type VerifiedCertificate struct {
	fingerprint    string
	attestedSerial string
	consumed       bool
}

func (c VerifiedCertificate) Valid() bool            { return c.consumed && c.fingerprint != "" }
func (c VerifiedCertificate) Fingerprint() string    { return c.fingerprint }
func (c VerifiedCertificate) AttestedSerial() string { return c.attestedSerial }

type Attestation struct {
	IssuerPEM   []byte
	Provisioner string
}
type Handoff struct {
	Directory string
	MaxAge    time.Duration
	OwnerUID  *int
}

func (h Handoff) owner() int {
	if h.OwnerUID != nil {
		return *h.OwnerUID
	}
	return os.Geteuid()
}
func (h Handoff) openDir(create bool) (int, error) {
	if !filepath.IsAbs(h.Directory) || filepath.Clean(h.Directory) != h.Directory || h.Directory == "/" || h.MaxAge <= 0 || h.MaxAge > MaxHandoffAge {
		return -1, errors.New("invalid private handoff configuration")
	}
	created := false
	if create {
		err := os.Mkdir(h.Directory, 0700)
		if err == nil {
			created = true
		} else if !os.IsExist(err) {
			return -1, errors.New("handoff directory unavailable")
		}
	}
	fd, err := unix.Open(h.Directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, errors.New("private handoff directory unavailable")
	}
	fail := func() (int, error) {
		_ = unix.Close(fd)
		return -1, errors.New("unsafe handoff directory ownership or permissions")
	}
	if created && h.owner() != os.Geteuid() {
		if os.Geteuid() != 0 || unix.Fchown(fd, h.owner(), -1) != nil {
			return fail()
		}
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0777 != 0700 || int(st.Uid) != h.owner() {
		return fail()
	}
	return fd, nil
}
func ReadLeaf(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("verified leaf unavailable")
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, errors.New("verified leaf must be a regular public certificate file")
	}
	defer func() { _ = f.Close() }()
	return readLeafPEM(f)
}
func readLeafPEM(f *os.File) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(f, MaxLeafBytes+1))
	if err != nil || len(data) > MaxLeafBytes {
		return nil, errors.New("verified leaf exceeds limit")
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytesTrimSpace(rest)) != 0 {
		return nil, errors.New("invalid verified leaf PEM")
	}
	return data, nil
}
func bytesTrimSpace(v []byte) []byte {
	start, end := 0, len(v)
	for start < end && (v[start] == ' ' || v[start] == '\t' || v[start] == '\n' || v[start] == '\r') {
		start++
	}
	for end > start && (v[end-1] == ' ' || v[end-1] == '\t' || v[end-1] == '\n' || v[end-1] == '\r') {
		end--
	}
	return v[start:end]
}

// Record is called only by the completed FreeRADIUS TLS verification hook. It never
// overwrites a token. A root helper can set OwnerUID to the separate daemon UID.
func (h Handoff) Record(leafFile, token string, attestation *Attestation, now time.Time) error {
	data, err := ReadLeaf(leafFile)
	if err != nil {
		return err
	}
	return h.RecordPEM(data, token, attestation, now)
}

// RecordPEM keeps the root helper's parsed bytes bound to the recorded fingerprint;
// it never reopens a replaceable FreeRADIUS temporary file after validation.
func (h Handoff) RecordPEM(data []byte, token string, attestation *Attestation, now time.Time) error {
	if !tokenPattern.MatchString(token) {
		return errors.New("invalid server certificate session token")
	}
	if len(data) > MaxLeafBytes {
		return errors.New("verified leaf exceeds limit")
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytesTrimSpace(rest)) != 0 {
		return errors.New("invalid verified leaf PEM")
	}
	var err error
	sum := sha256.Sum256(block.Bytes)
	fingerprint := hex.EncodeToString(sum[:])
	value := []byte(fingerprint)
	if attestation != nil {
		if serial := RecognizeAttested(data, attestation.IssuerPEM, attestation.Provisioner, now); serial != "" {
			value, err = json.Marshal(struct {
				Fingerprint    string `json:"fingerprint"`
				AttestedSerial string `json:"attested_serial"`
			}{fingerprint, serial})
			if err != nil {
				return err
			}
		}
	}
	dir, err := h.openDir(true)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(dir) }()
	fd, err := unix.Openat(dir, token, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errors.New("certificate handoff already exists or cannot be created")
	}
	f := os.NewFile(uintptr(fd), token)
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = unix.Unlinkat(dir, token, 0)
		}
	}()
	if h.owner() != os.Geteuid() {
		if os.Geteuid() != 0 || unix.Fchown(fd, h.owner(), -1) != nil {
			return errors.New("handoff ownership could not be assigned")
		}
	}
	if err := f.Chmod(0600); err != nil {
		return errors.New("private handoff permissions unavailable")
	}
	if _, err := f.Write(value); err != nil {
		return errors.New("certificate handoff write failed")
	}
	if err := f.Close(); err != nil {
		return errors.New("certificate handoff close failed")
	}
	ok = true
	return nil
}

// Consume never follows links, waits for locks, or validates an accessible reusable
// token. Unlink occurs under an exclusive lock before any content/age validation.
func (h Handoff) Consume(token string, now time.Time) (VerifiedCertificate, error) {
	deny := func() (VerifiedCertificate, error) {
		return VerifiedCertificate{}, errors.New("invalid, expired or consumed certificate handoff")
	}
	if !tokenPattern.MatchString(token) {
		return deny()
	}
	dir, err := h.openDir(false)
	if err != nil {
		return deny()
	}
	defer func() { _ = unix.Close(dir) }()
	fd, err := unix.Openat(dir, token, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return deny()
	}
	f := os.NewFile(uintptr(fd), token)
	defer func() { _ = f.Close() }()
	if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return deny()
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&0777 != 0600 || int(st.Uid) != h.owner() {
		return deny()
	}
	var named unix.Stat_t
	if unix.Fstatat(dir, token, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || named.Dev != st.Dev || named.Ino != st.Ino {
		return deny()
	}
	if unix.Unlinkat(dir, token, 0) != nil {
		return deny()
	}
	info, err := f.Stat()
	if err != nil {
		return deny()
	}
	mtime := info.ModTime()
	if !domain.Fresh(domain.Unix(mtime), now, h.MaxAge) {
		return deny()
	}
	value, err := io.ReadAll(io.LimitReader(f, MaxHandoffBytes+1))
	if err != nil || len(value) > MaxHandoffBytes {
		return deny()
	}
	fingerprint, serial := string(value), ""
	if len(value) > 0 && value[0] == '{' {
		var binding struct {
			Fingerprint    string `json:"fingerprint"`
			AttestedSerial string `json:"attested_serial"`
		}
		if domain.DecodeJSONStrict(value, &binding) != nil || !serialPattern.MatchString(binding.AttestedSerial) {
			return deny()
		}
		fingerprint, serial = binding.Fingerprint, binding.AttestedSerial
	}
	fingerprint, err = domain.NormalizeFingerprint(fingerprint)
	if err != nil {
		return deny()
	}
	return VerifiedCertificate{fingerprint: fingerprint, attestedSerial: serial, consumed: true}, nil
}

// CheckDowngradeGuard preserves the sticky fingerprint-required marker across restarts.
// Existing markers (including links or malformed state) always prevent legacy downgrade.
func CheckDowngradeGuard(path string, fingerprintMode, dryRun bool) error {
	_, err := os.Lstat(path)
	if !fingerprintMode {
		if err == nil || !os.IsNotExist(err) {
			return errors.New("legacy serial mode refused: fingerprint downgrade guard exists or cannot be checked")
		}
		return nil
	}
	if err == nil {
		return nil
	}
	if !os.IsNotExist(err) {
		return errors.New("fingerprint downgrade guard unavailable")
	}
	if dryRun {
		return nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(err) {
		return nil
	}
	if err != nil {
		return errors.New("cannot persist fingerprint downgrade guard")
	}
	_, err = f.WriteString("fingerprint-required\n")
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	return err
}
