package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const ArtifactDirectory = "/var/cache/cloud-8021x/artifacts"
const ArtifactManifest = ArtifactDirectory + "/manifest.json"
const RadiusVersion = "3.2.10+dfsg-2~bookworm+campus3"

var requiredArtifacts = []string{"freeradius", "freeradius-common", "freeradius-config", "freeradius-utils", "freeradius-rest", "freeradius-postgresql", "libfreeradius3", "step-ca", "step-cli", "step-kms-plugin", "datadog-agent", "datadog-agent-ddot"}

type Artifact struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	SHA256       string `json:"sha256"`
}
type Manifest struct {
	CollectorSHA256    string     `json:"collector_sha256"`
	ApplicationVersion string     `json:"application_version"`
	ApplicationSHA256  string     `json:"application_sha256"`
	ConfigSHA256       string     `json:"config_sha256"`
	Schema             int        `json:"schema"`
	Architecture       string     `json:"architecture"`
	Artifacts          []Artifact `json:"artifacts"`
}

func radiusPackage(name string) bool {
	return strings.HasPrefix(name, "freeradius") || name == "libfreeradius3"
}
func (a Artifact) filename() string { return a.Name + "_" + a.Version + "_" + a.Architecture + ".deb" }
func (m Manifest) Validate(arch string) error {
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(m.CollectorSHA256) || m.Schema != 1 || (arch != "amd64" && arch != "arm64") || m.Architecture != arch || len(m.Artifacts) != len(requiredArtifacts) {
		return errors.New("unsupported or incomplete protected artifact manifest")
	}
	seen := map[string]bool{}
	for _, a := range m.Artifacts {
		if !slices.Contains(requiredArtifacts, a.Name) || seen[a.Name] || !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.+~:-]{0,95}$`).MatchString(a.Version) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(a.SHA256) || (a.Architecture != arch && (a.Name != "freeradius-common" || a.Architecture != "all")) {
			return errors.New("unapproved artifact identity, checksum or architecture")
		}
		if radiusPackage(a.Name) && a.Version != RadiusVersion {
			return errors.New("coherent reviewed campus3 FreeRADIUS family required")
		}
		seen[a.Name] = true
	}
	var agent, collector string
	for _, a := range m.Artifacts {
		if a.Name == "datadog-agent" {
			agent = a.Version
		}
		if a.Name == "datadog-agent-ddot" {
			collector = a.Version
		}
	}
	if agent != collector {
		return errors.New("matched Agent and DDOT package versions required")
	}
	return nil
}

// rootFile pins all ancestors and checks a single-link root-owned regular input.
// Callers supply fixed product paths, never CLI-selected files.
func rootFile(path string, maximum int64) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("unsafe protected input path")
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, part := range parts[:len(parts)-1] {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if e != nil {
			if errors.Is(e, unix.ENOENT) {
				return nil, os.ErrNotExist
			}
			return nil, errors.New("unsafe protected input ancestry")
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&0022 != 0 {
			_ = unix.Close(fd)
			return nil, errors.New("unprotected input ancestry")
		}
	}
	defer func() { _ = unix.Close(fd) }()
	leaf, e := unix.Openat(fd, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	var st unix.Stat_t
	if unix.Fstat(leaf, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Nlink != 1 || st.Mode&0022 != 0 || st.Size < 0 || st.Size > maximum {
		_ = unix.Close(leaf)
		return nil, errors.New("unsafe protected input file")
	}
	return os.NewFile(uintptr(leaf), "protected-input"), nil
}
func LoadManifest() (Manifest, error) {
	var m Manifest
	f, e := rootFile(ArtifactManifest, 65536)
	if e != nil {
		return m, errors.New("protected artifact manifest unavailable")
	}
	defer func() { _ = f.Close() }()
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&m) != nil {
		return m, errors.New("invalid artifact manifest")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return m, errors.New("trailing artifact manifest data")
	}
	return m, m.Validate(runtime.GOARCH)
}

type commandRunner func(context.Context, string, ...string) ([]byte, error)

// execute is package-private: exported operations select their own fixed commands.
func execute(ctx context.Context, path string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "HOME=/nonexistent", "DEBIAN_FRONTEND=noninteractive"}
	if path == "/usr/bin/dpkg" {
		cmd.Env = append(cmd.Env, "DOCKER_DD_AGENT=1")
	}
	var output boundedOutput
	cmd.Stdout = &output
	cmd.Stderr = &output
	if e := cmd.Run(); e != nil {
		return nil, errors.New("fixed host operation failed")
	}
	return output.data, nil
}

type boundedOutput struct{ data []byte }

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := (64 << 10) - len(b.data)
	if remaining > 0 {
		b.data = append(b.data, p[:min(len(p), remaining)]...)
	}
	return n, nil
}
func verifyArtifacts(ctx context.Context, m Manifest, run commandRunner) error {
	if e := m.Validate(runtime.GOARCH); e != nil {
		return e
	}
	for _, a := range m.Artifacts {
		path := filepath.Join(ArtifactDirectory, a.filename())
		f, e := rootFile(path, 1<<30)
		if e != nil {
			return errors.New("protected artifact unavailable")
		}
		sum := sha256.New()
		_, e = io.Copy(sum, f)
		_ = f.Close()
		if e != nil || hex.EncodeToString(sum.Sum(nil)) != a.SHA256 {
			return errors.New("artifact checksum rejected")
		}
		out, e := run(ctx, "/usr/bin/dpkg-deb", "--show", "--showformat=${Package}\t${Version}\t${Architecture}", path)
		if e != nil || string(out) != a.Name+"\t"+a.Version+"\t"+a.Architecture {
			return errors.New("debian artifact metadata differs from manifest")
		}
	}
	return nil
}

// VerifyArtifacts is read-only and validates every byte before installation.
func VerifyArtifacts(ctx context.Context, m Manifest) error { return verifyArtifacts(ctx, m, execute) }

// InstallArtifacts must be called within the shared maintenance operation after
// the active-node peer gate. Maintainer scripts cannot stop/start services. No
// network package resolution, upgrade, arbitrary package or fallback is allowed.
func InstallArtifacts(ctx context.Context, m Manifest) error {
	if os.Geteuid() != 0 {
		return errors.New("artifact installation requires root")
	}
	if e := CheckShippingPlatform(); e != nil {
		return e
	}
	if e := VerifyArtifacts(ctx, m); e != nil {
		return e
	}
	return withPackagePolicy(ctx, func() error {
		args := []string{"--force-confold", "--install"}
		for _, a := range m.Artifacts {
			args = append(args, filepath.Join(ArtifactDirectory, a.filename()))
		}
		if _, e := execute(ctx, "/usr/bin/dpkg", args...); e != nil {
			return errors.New("pinned package installation failed; maintenance remains blocked")
		}
		for _, a := range m.Artifacts {
			out, e := execute(ctx, "/usr/bin/dpkg-query", "--show", "--showformat=${db:Status-Abbrev}\t${Version}\t${Architecture}", a.Name)
			if e != nil || strings.TrimSpace(string(out)) != "ii \t"+a.Version+"\t"+a.Architecture {
				return fmt.Errorf("package %s is not fully configured at the pinned version", a.Name)
			}
		}
		return nil
	})
}

// IncomingFiles exposes no path selector: the verified downloader places only
// these two fixed incoming artifacts. Go backs up the actual active files inside
// its maintenance transaction before publishing either incoming file.
func IncomingFiles() ([]File, error) {
	manifest, e := LoadManifest()
	if e != nil {
		return nil, e
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.+-]{0,95}$`).MatchString(manifest.ApplicationVersion) {
		return nil, errors.New("incoming application version missing")
	}
	files := []File{}
	for _, item := range []struct {
		source, target, hash string
		mode                 uint32
		limit                int64
	}{
		{ArtifactDirectory + "/cloud-8021x", "/usr/local/bin/cloud-8021x", manifest.ApplicationSHA256, 0755, 256 << 20},
		{ArtifactDirectory + "/config.yaml", "/etc/cloud-8021x/config.yaml", manifest.ConfigSHA256, 0644, 1 << 20},
	} {
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(item.hash) {
			return nil, errors.New("mandatory incoming checksum missing")
		}
		f, e := rootFile(item.source, item.limit)
		if e != nil {
			return nil, e
		}
		data, e := io.ReadAll(f)
		_ = f.Close()
		if e != nil {
			return nil, e
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != item.hash {
			return nil, errors.New("incoming release checksum rejected")
		}
		files = append(files, File{Path: item.target, Data: data, Mode: item.mode})
	}
	return files, nil
}
