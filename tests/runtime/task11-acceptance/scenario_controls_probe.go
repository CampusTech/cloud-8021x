package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

var controlUnitProperties = []string{"Id", "LoadState", "ActiveState", "SubState", "MainPID", "ControlGroup", "FragmentPath", "DropInPaths"}

func parseControlProperties(raw []byte, name string) (map[string]string, error) {
	if len(raw) == 0 || len(raw) > 16<<10 || !slices.Contains([]string{"cloud-8021x.service", "freeradius.service", "step-ca.service", "step-ca-rsa.service", "datadog-agent.service", "datadog-agent-ddot.service", "task11-node-green-primary.service", "task11-postgres.service"}, name) {
		return nil, errScenarioControl
	}
	p := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok || !slices.Contains(controlUnitProperties, k) {
			return nil, errScenarioControl
		}
		if _, ok = p[k]; ok {
			return nil, errScenarioControl
		}
		p[k] = v
	}
	if len(p) != len(controlUnitProperties) || p["Id"] != name || p["LoadState"] != "loaded" || !controlUnitFiles(name, p["FragmentPath"], p["DropInPaths"]) {
		return nil, errScenarioControl
	}
	pid, err := strconv.Atoi(p["MainPID"])
	if err != nil || pid < 0 || strconv.Itoa(pid) != p["MainPID"] {
		return nil, errScenarioControl
	}
	if p["ControlGroup"] != "" && p["ControlGroup"] != "/system.slice/"+name {
		return nil, errScenarioControl
	}
	return p, nil
}
func parseControlCollector(raw []byte) (sc.CollectorObservation, error) {
	var out sc.CollectorObservation
	if len(raw) == 0 || len(raw) > 1<<20 {
		return out, errScenarioControl
	}
	count := 0
	target := "/var/lib/cloud8021x/collector"
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) < 10 {
			continue
		}
		if strings.HasPrefix(f[4], target+"/") {
			return out, errScenarioControl
		}
		if f[4] != target {
			continue
		}
		count++
		dash := slices.Index(f, "-")
		if dash < 6 || len(f) != dash+4 || f[3] != "/" || f[dash+1] != "ext4" || !strings.HasPrefix(f[dash+2], "/dev/loop") {
			return out, errScenarioControl
		}
		ordinal, err := strconv.ParseUint(strings.TrimPrefix(f[dash+2], "/dev/loop"), 10, 32)
		if err != nil || f[dash+2] != "/dev/loop"+strconv.FormatUint(ordinal, 10) || f[2] != "7:"+strconv.FormatUint(ordinal, 10) {
			return out, errScenarioControl
		}
		out = sc.CollectorObservation{BackingFile: "/var/lib/cloud-8021x-bootstrap/collector.ext4", Filesystem: f[dash+1], MountDevice: f[dash+2], Options: strings.Split(f[5], ","), MountActive: true}
		for _, n := range []string{"rw", "nodev", "nosuid", "noexec"} {
			if !slices.Contains(out.Options, n) {
				return out, errScenarioControl
			}
		}
		seen := map[string]bool{}
		for _, n := range out.Options {
			if seen[n] || n == "ro" || n == "exec" || n == "suid" || n == "dev" {
				return out, errScenarioControl
			}
			seen[n] = true
		}
	}
	if count != 1 {
		return out, errScenarioControl
	}
	return out, nil
}
func parseControlIntake(raw []byte, pin string) (bool, error) {
	var fields map[string]json.RawMessage
	if len(raw) > 32<<20 || !validSHA(pin) || decodeExactJSON(raw, &fields) != nil || len(fields) != 10 {
		return false, errScenarioControl
	}
	for _, name := range []string{"peers", "seed_sha256", "events", "batches", "commands", "submission_uncertain", "inventory_error", "intake_unavailable", "schema", "secrets"} {
		if fields[name] == nil {
			return false, errScenarioControl
		}
	}
	var schema int
	var seed string
	var unavailable bool
	if json.Unmarshal(fields["schema"], &schema) != nil || schema != 1 || json.Unmarshal(fields["seed_sha256"], &seed) != nil || seed != pin || (string(fields["intake_unavailable"]) != "true" && string(fields["intake_unavailable"]) != "false") || json.Unmarshal(fields["intake_unavailable"], &unavailable) != nil {
		return false, errScenarioControl
	}
	return unavailable, nil
}
func decodeControlProbeInput(raw []byte, hostname, app, config string) (sc.Request, error) {
	var in controlProbeInput
	var fields map[string]json.RawMessage
	if len(raw) > maxScenarioNodeInput || decodeExactJSON(raw, &in) != nil || decodeExactJSON(raw, &fields) != nil || len(fields) != 4 || fields["services"] == nil || fields["schema"] == nil || fields["request_bytes"] == nil || fields["config_sha256"] == nil || in.Schema != 1 || !validSHA(app) || !validSHA(config) || in.ConfigSHA256 != config || (hostname != "task11-green-primary" && hostname != "task11-green-secondary") {
		return sc.Request{}, errScenarioControl
	}
	if _, err := controlDecodeServices(raw); err != nil {
		return sc.Request{}, errScenarioControl
	}
	r, err := sc.DecodeRequest(in.RequestBytes)
	if err != nil || r.ApplicationSHA256 != app || !slices.Contains([]string{"probe-active-pair", "stop-green-primary", "reboot-green-primary", "start-green-primary"}, r.Action) || (r.Action != "probe-active-pair" && hostname != "task11-green-primary") || filepath.Clean(hostname) != hostname {
		return sc.Request{}, errScenarioControl
	}
	return r, nil
}

func controlUnitFiles(name, fragment, drops string) bool {
	wantFragment := "/etc/systemd/system/" + name
	wantDrops := ""
	if !strings.HasPrefix(name, "task11-") {
		wantDrops = "/etc/systemd/system/" + name + ".d/parallel.conf"
	}
	if name == "freeradius.service" {
		if fragment != "/usr/lib/systemd/system/"+name && fragment != "/lib/systemd/system/"+name {
			return false
		}
		wantFragment = fragment
		wantDrops = "/etc/systemd/system/" + name + ".d/cloud-8021x.conf " + wantDrops
	}
	if name == "datadog-agent.service" {
		wantDrops = "/etc/systemd/system/" + name + ".d/cloud-8021x.conf " + wantDrops
	}
	return fragment == wantFragment && drops == wantDrops
}

// Fixed callers choose the path/owner/mode. The retained directory and no-follow
// leaf checks do not widen private control input ownership or permissions.
func controlProtectedFile(path string, uid int, mode uint32, max int64) ([]byte, error) {
	parent, err := privateParent(path, uid)
	if err != nil {
		return nil, errScenarioControl
	}
	defer func() { _ = unix.Close(parent) }()
	fd, err := unix.Openat(parent, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errScenarioControl
	}
	f := os.NewFile(uintptr(fd), "fixed-control-measurement")
	defer func() { _ = f.Close() }()
	var before, after, leaf unix.Stat_t
	if unix.Fstat(fd, &before) != nil || int(before.Uid) != uid || before.Mode&unix.S_IFMT != unix.S_IFREG || uint32(before.Mode&07777) != mode || before.Nlink != 1 || before.Size > max {
		return nil, errScenarioControl
	}
	first, err := f.Stat()
	if err != nil {
		return nil, errScenarioControl
	}
	raw, err := boundedInput(f, max)
	last, statErr := f.Stat()
	if err != nil || statErr != nil || !os.SameFile(first, last) || !first.ModTime().Equal(last.ModTime()) || unix.Fstat(fd, &after) != nil || unix.Fstatat(parent, filepath.Base(path), &leaf, unix.AT_SYMLINK_NOFOLLOW) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mode != after.Mode || before.Uid != after.Uid || before.Nlink != after.Nlink || leaf.Dev != before.Dev || leaf.Ino != before.Ino {
		clear(raw)
		return nil, errScenarioControl
	}
	fresh, er := privateParent(path, uid)
	if er != nil {
		clear(raw)
		return nil, errScenarioControl
	}
	defer func() { _ = unix.Close(fresh) }()
	var parentBefore, parentAfter unix.Stat_t
	if unix.Fstat(parent, &parentBefore) != nil || unix.Fstat(fresh, &parentAfter) != nil || parentBefore.Dev != parentAfter.Dev || parentBefore.Ino != parentAfter.Ino {
		clear(raw)
		return nil, errScenarioControl
	}
	return raw, nil
}

func controlFragmentPath(path string) string {
	if strings.HasPrefix(path, "/lib/systemd/system/") {
		return "/usr" + path
	}
	return path
}

func controlStreamDigest(f *os.File, max int64) (string, error) {
	if f == nil || max < 1 || max > 256<<20 {
		return "", errScenarioControl
	}
	hash := sha256.New()
	var buffer [32 << 10]byte
	n, err := io.CopyBuffer(hash, io.LimitReader(f, max+1), buffer[:])
	if err != nil || n > max {
		return "", errScenarioControl
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// Package-derived executable and exact shipping unit pins are private transport
// data. No caller may turn a current installed pathname into expected authority.
type controlServiceAuthority struct {
	ExecutableSHA256 string            `json:"executable_sha256"`
	Files            map[string]string `json:"files"`
}

var controlShippingUnits = []string{"cloud-8021x.service", "freeradius.service", "step-ca.service", "step-ca-rsa.service", "datadog-agent.service", "datadog-agent-ddot.service"}

func controlServicePaths(name string) []string {
	if !slices.Contains(controlShippingUnits, name) {
		return nil
	}
	fragment := "/etc/systemd/system/" + name
	if name == "freeradius.service" {
		fragment = "/usr/lib/systemd/system/" + name
	}
	out := []string{fragment}
	if name == "freeradius.service" || name == "datadog-agent.service" {
		out = append(out, "/etc/systemd/system/"+name+".d/cloud-8021x.conf")
	}
	return append(out, "/etc/systemd/system/"+name+".d/parallel.conf")
}
func validateControlAuthority(name string, authority controlServiceAuthority) error {
	paths := controlServicePaths(name)
	if len(paths) == 0 || len(authority.Files) != len(paths) || !validSHA(authority.ExecutableSHA256) {
		return errScenarioControl
	}
	for _, path := range paths {
		if !validSHA(authority.Files[path]) {
			return errScenarioControl
		}
	}
	return nil
}
func validateControlShipping(name, digest string, files map[string][]byte, authority controlServiceAuthority) error {
	if validateControlAuthority(name, authority) != nil || digest != authority.ExecutableSHA256 || len(files) != len(authority.Files) {
		return errScenarioControl
	}
	for path, pin := range authority.Files {
		raw, ok := files[path]
		if !ok || adoption.Digest(raw) != pin {
			return errScenarioControl
		}
	}
	return nil
}

// The only private probe extension is a closed six-service authority map derived
// by the outer controller from independently authenticated package/render bytes.
type controlProbeInput struct {
	Schema       int                                `json:"schema"`
	RequestBytes []byte                             `json:"request_bytes"`
	ConfigSHA256 string                             `json:"config_sha256"`
	Services     map[string]controlServiceAuthority `json:"services"`
}

func controlDecodeServices(raw []byte) (map[string]controlServiceAuthority, error) {
	var in controlProbeInput
	var top map[string]json.RawMessage
	if decodeExactJSON(raw, &in) != nil || decodeExactJSON(raw, &top) != nil || len(top) != 4 || top["schema"] == nil || top["request_bytes"] == nil || top["config_sha256"] == nil || top["services"] == nil || len(in.Services) != 6 {
		return nil, errScenarioControl
	}
	var services map[string]json.RawMessage
	if decodeExactJSON(top["services"], &services) != nil || len(services) != 6 {
		return nil, errScenarioControl
	}
	for _, name := range controlShippingUnits {
		var fields map[string]json.RawMessage
		if decodeExactJSON(services[name], &fields) != nil || len(fields) != 2 || fields["executable_sha256"] == nil || fields["files"] == nil || validateControlAuthority(name, in.Services[name]) != nil {
			return nil, errScenarioControl
		}
	}
	return in.Services, nil
}

// Validate the small fixed Debian ar envelope without extracting to disk. The
// enclosing caller already checked the exact retained archive's SHA and inode.
func controlDebData(f *os.File) (*io.SectionReader, string, error) {
	if f == nil {
		return nil, "", errScenarioControl
	}
	st, err := f.Stat()
	if err != nil || st.Size() < 8 || st.Size() > 256<<20 {
		return nil, "", errScenarioControl
	}
	var magic [8]byte
	if _, err = f.ReadAt(magic[:], 0); err != nil || string(magic[:]) != "!<arch>\n" {
		return nil, "", errScenarioControl
	}
	offset := int64(8)
	seen := map[string]bool{}
	var data *io.SectionReader
	kind := ""
	for offset < st.Size() {
		var header [60]byte
		if _, err = f.ReadAt(header[:], offset); err != nil || string(header[58:]) != "`\n" {
			return nil, "", errScenarioControl
		}
		name := strings.TrimSuffix(strings.TrimSpace(string(header[:16])), "/")
		sizeText := strings.TrimSpace(string(header[48:58]))
		size, er := strconv.ParseInt(sizeText, 10, 64)
		offset += 60
		if er != nil || size < 0 || strconv.FormatInt(size, 10) != sizeText || size > st.Size()-offset || seen[name] {
			return nil, "", errScenarioControl
		}
		seen[name] = true
		switch name {
		case "debian-binary":
			var version [4]byte
			if size != 4 {
				return nil, "", errScenarioControl
			}
			if _, er = f.ReadAt(version[:], offset); er != nil || string(version[:]) != "2.0\n" {
				return nil, "", errScenarioControl
			}
		case "control.tar.gz", "control.tar.xz":
			if size == 0 {
				return nil, "", errScenarioControl
			}
		case "data.tar.gz", "data.tar.xz":
			if data != nil || size == 0 {
				return nil, "", errScenarioControl
			}
			data = io.NewSectionReader(f, offset, size)
			kind = strings.TrimPrefix(name, "data.tar.")
		default:
			return nil, "", errScenarioControl
		}
		offset += size
		if size%2 != 0 {
			var pad [1]byte
			if _, er = f.ReadAt(pad[:], offset); er != nil || pad[0] != '\n' {
				return nil, "", errScenarioControl
			}
			offset++
		}
	}
	if offset != st.Size() || len(seen) != 3 || !seen["debian-binary"] || !seen["control.tar."+kind] || data == nil {
		return nil, "", errScenarioControl
	}
	return data, kind, nil
}
func controlTarDigests(input io.Reader, paths []string) (map[string]string, error) {
	if input == nil || len(paths) == 0 || len(paths) > 2 {
		return nil, errScenarioControl
	}
	targets := map[string]bool{}
	for _, path := range paths {
		if filepath.Clean(path) != path || !strings.HasPrefix(path, "/") || targets[path] {
			return nil, errScenarioControl
		}
		targets[path] = true
	}
	// A fixed package projection is streamed; unrelated payloads are not retained.
	limit := &io.LimitedReader{R: input, N: (1 << 30) + 1}
	reader := tar.NewReader(limit)
	found := map[string]string{}
	for count := 0; ; count++ {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil || count >= 200000 {
			return nil, errScenarioControl
		}
		name := strings.TrimPrefix(header.Name, "./")
		path := "/" + name
		if header.Typeflag == tar.TypeDir && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}
		if strings.HasPrefix(name, "/") || filepath.Clean(path) != path || strings.Contains(name, "\\") {
			return nil, errScenarioControl
		}
		path = controlFragmentPath(path)
		if !targets[path] {
			continue
		}
		if found[path] != "" || header.Typeflag != tar.TypeReg || header.Uid != 0 || header.Gid != 0 || header.Mode&0022 != 0 || header.Size < 1 || header.Size > 256<<20 {
			return nil, errScenarioControl
		}
		hash := sha256.New()
		var buffer [32 << 10]byte
		if !strings.HasSuffix(path, ".service") {
			var magic [4]byte
			if header.Mode&0111 == 0 || header.Size < 4 {
				return nil, errScenarioControl
			}
			if _, err = io.ReadFull(reader, magic[:]); err != nil || !bytes.Equal(magic[:], []byte{0x7f, 'E', 'L', 'F'}) {
				return nil, errScenarioControl
			}
			_, _ = hash.Write(magic[:])
		} else if header.Size > 32<<10 {
			return nil, errScenarioControl
		}
		if _, err = io.CopyBuffer(hash, reader, buffer[:]); err != nil {
			return nil, errScenarioControl
		}
		found[path] = hex.EncodeToString(hash.Sum(nil))
	}
	var buffer [32 << 10]byte
	if _, err := io.CopyBuffer(io.Discard, limit, buffer[:]); err != nil || limit.N < 1 || len(found) != len(targets) {
		return nil, errScenarioControl
	}
	return found, nil
}

func controlPlanAuthority(raw []byte, pin string) (string, string, error) {
	var fields map[string]json.RawMessage
	var schema int
	var packages, lower string
	if len(raw) > 1<<20 || !validSHA(pin) || adoption.Digest(raw) != pin || decodeExactJSON(raw, &fields) != nil || json.Unmarshal(fields["Schema"], &schema) != nil || schema != 1 || json.Unmarshal(fields["PackageManifestSHA256"], &packages) != nil || json.Unmarshal(fields["LowerManifestSHA256"], &lower) != nil || !validSHA(packages) || !validSHA(lower) {
		return "", "", errScenarioControl
	}
	return packages, lower, nil
}
func controlLowerXZ(raw []byte, pin string) (string, error) {
	var lower struct {
		Schema  int
		Entries []struct {
			Path, Kind, SHA256, Target string
			Mode                       uint32
			Bytes                      int64
		}
	}
	if len(raw) > 32<<20 || !validSHA(pin) || adoption.Digest(raw) != pin || decodeExactJSON(raw, &lower) != nil || lower.Schema != 1 || len(lower.Entries) > 200000 {
		return "", errScenarioControl
	}
	found := ""
	for _, entry := range lower.Entries {
		if entry.Path != "/usr/bin/xz" {
			continue
		}
		if found != "" || entry.Kind != "file" || entry.Mode&0022 != 0 || entry.Mode&0111 == 0 || entry.Bytes < 1 || entry.Bytes > 32<<20 || !validSHA(entry.SHA256) {
			return "", errScenarioControl
		}
		found = entry.SHA256
	}
	if found == "" {
		return "", errScenarioControl
	}
	return found, nil
}
func controlPackagePins(raw []byte, pin string) (map[string]host.Artifact, error) {
	var packageInput struct {
		Schema          int             `json:"schema"`
		Architecture    string          `json:"architecture"`
		CollectorSHA256 string          `json:"collector_sha256"`
		Artifacts       []host.Artifact `json:"artifacts"`
	}
	var fields map[string]json.RawMessage
	if len(raw) > 1<<20 || !validSHA(pin) || adoption.Digest(raw) != pin || decodeExactJSON(raw, &packageInput) != nil || decodeExactJSON(raw, &fields) != nil || len(fields) != 4 || fields["schema"] == nil || fields["architecture"] == nil || fields["collector_sha256"] == nil || fields["artifacts"] == nil || packageInput.Schema != 1 || packageInput.Architecture != "arm64" || !validSHA(packageInput.CollectorSHA256) || len(packageInput.Artifacts) != 62 {
		return nil, errScenarioControl
	}
	var wire []map[string]json.RawMessage
	if decodeExactJSON(fields["artifacts"], &wire) != nil || len(wire) != 62 {
		return nil, errScenarioControl
	}
	versions := map[string]string{"freeradius": host.RadiusVersion, "step-ca": host.StepCAVersion, "datadog-agent": host.MonitoringVersion, "datadog-agent-ddot": host.MonitoringVersion}
	out := map[string]host.Artifact{}
	seen := map[string]bool{}
	for i, a := range packageInput.Artifacts {
		m := wire[i]
		if len(m) != 4 || m["name"] == nil || m["version"] == nil || m["architecture"] == nil || m["sha256"] == nil || a.Name == "" || seen[a.Name] {
			return nil, errScenarioControl
		}
		seen[a.Name] = true
		version, ok := versions[a.Name]
		if !ok {
			continue
		}
		if a.Version != version || a.Architecture != "arm64" || !validSHA(a.SHA256) {
			return nil, errScenarioControl
		}
		out[a.Name] = a
	}
	if len(out) != 4 {
		return nil, errScenarioControl
	}
	return out, nil
}

// Join the actual decoder completion before ordinary retirement cleanup. A
// failed parser or expired deadline first kills the owned decoder subtree.
func controlDecoderWait(ctx context.Context, done <-chan error, failed bool, kill func() error) error {
	if failed {
		_ = kill()
		return <-done
	}
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		_ = kill()
		return <-done
	}
}
