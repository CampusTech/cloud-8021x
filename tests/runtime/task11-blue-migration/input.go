package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	seed "github.com/CampusTech/cloud-8021x/tests/runtime/task11-assembly-seed/contract"
	"golang.org/x/sys/unix"
)

type plan struct {
	Schema                                                    int
	MachineID, ConfigSHA256, InputSHA256, DSNSHA256, CASHA256 string
}
type prepared struct {
	Config config.Config
	DSN    string
}

func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func readAt(root int, name string, uid, mode uint32, limit int64) ([]byte, error) {
	if path.IsAbs(name) || path.Clean(name) != name || strings.HasPrefix(name, "../") || name == "." || limit < 1 {
		return nil, errors.New("fixed relative protected input required")
	}
	fd, err := unix.Dup(root)
	if err != nil {
		return nil, errors.New("protected directory unavailable")
	}
	defer func() { _ = unix.Close(fd) }()
	parts := strings.Split(name, "/")
	for _, part := range parts[:len(parts)-1] {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return nil, errors.New("protected input ancestry refused")
		}
		var st unix.Stat_t
		if unix.Fstat(next, &st) != nil || st.Uid != uid || st.Mode&0022 != 0 {
			_ = unix.Close(next)
			return nil, errors.New("protected input ancestry refused")
		}
		_ = unix.Close(fd)
		fd = next
	}
	leaf, err := unix.Openat(fd, parts[len(parts)-1], unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("protected input unavailable")
	}
	f := os.NewFile(uintptr(leaf), "private-input")
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if unix.Fstat(leaf, &st) != nil || st.Uid != uid || st.Nlink != 1 || st.Mode&unix.S_IFMT != unix.S_IFREG || (mode != 0 && uint32(st.Mode)&0777 != mode) || (mode == 0 && st.Mode&0022 != 0) || st.Size < 1 || st.Size > limit {
		return nil, errors.New("protected input owner/mode/size differs")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, errors.New("protected input read refused")
	}
	return b, nil
}
func readFixed(name string, mode uint32, limit int64) ([]byte, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("root unavailable")
	}
	defer func() { _ = unix.Close(fd) }()
	return readAt(fd, strings.TrimPrefix(name, "/"), 0, mode, limit)
}
func validateMaterial(p plan, inputRaw, cfgRaw, api, dsn, ca []byte) (prepared, error) {
	var out prepared
	if p.Schema != 1 {
		return out, errors.New("blue migration plan schema differs")
	}
	for _, pin := range []string{p.ConfigSHA256, p.InputSHA256, p.DSNSHA256, p.CASHA256} {
		if !seed.IsSHA(pin) {
			return out, errors.New("independent migration input pins required")
		}
	}
	if digest(inputRaw) != p.InputSHA256 || digest(cfgRaw) != p.ConfigSHA256 || digest(dsn) != p.DSNSHA256 || digest(ca) != p.CASHA256 {
		return out, errors.New("independently pinned migration bytes differ")
	}
	var s seed.Input
	if domain.DecodeJSONStrict(inputRaw, &s) != nil || s.Validate() != nil || s.PostgresCA.SHA256 != p.CASHA256 || s.InstalledSeedSHA256 != digest(api) {
		return out, errors.New("finalized assembly seed binding differs")
	}
	c, err := config.Decode(bytes.NewReader(cfgRaw))
	if err != nil || validateBlueConfig(c, s.Project, p.CASHA256) != nil {
		return out, errors.New("exact validated original blue configuration required")
	}
	if err = validateDSN(dsn); err != nil {
		return out, err
	}
	var projection struct {
		Secrets map[string]map[string]string `json:"secrets"`
	}
	if json.Unmarshal(api, &projection) != nil {
		return out, errors.New("finalized private seed projection invalid")
	}
	versions := projection.Secrets["projects/"+seed.ProjectNumber+"/secrets/postgres-blue-migration-dsn"]
	original, e := base64.StdEncoding.Strict().DecodeString(versions["1"])
	if e != nil || len(versions) != 1 || !bytes.Equal(original, dsn) {
		return out, errors.New("migration credential differs from original finalized version")
	}
	block, rest := pem.Decode(ca)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return out, errors.New("single original PostgreSQL CA required")
	}
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil || !cert.IsCA {
		return out, errors.New("PostgreSQL CA invalid")
	}
	return prepared{c, string(dsn)}, nil
}
