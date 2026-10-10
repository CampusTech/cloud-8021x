package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
	"github.com/CampusTech/cloud-8021x/internal/templates/systemd"

	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

func TestScenarioControlsActualParserContracts(t *testing.T) {
	unit := []byte("Id=cloud-8021x.service\nLoadState=loaded\nActiveState=active\nSubState=running\nMainPID=123\nControlGroup=/system.slice/cloud-8021x.service\nFragmentPath=/etc/systemd/system/cloud-8021x.service\nDropInPaths=/etc/systemd/system/cloud-8021x.service.d/parallel.conf\n")
	if _, err := parseControlProperties(unit, "cloud-8021x.service"); err != nil {
		t.Fatal("actual unit refused", err)
	}
	for _, v := range []string{string(unit) + "Id=cloud-8021x.service\n", strings.Replace(string(unit), "MainPID=123", "MainPID=0123", 1), strings.Replace(string(unit), "DropInPaths=", "DropInPaths=/tmp/override.conf", 1), strings.Replace(string(unit), "/etc/systemd/system/", "/run/systemd/system/", 1)} {
		if _, err := parseControlProperties([]byte(v), "cloud-8021x.service"); err == nil {
			t.Fatal("ambiguous/foreign unit accepted")
		}
	}
	mount := []byte("12 1 7:3 / /var/lib/cloud8021x/collector rw,nodev,nosuid,noexec - ext4 /dev/loop3 rw\n")
	if v, err := parseControlCollector(mount); err != nil || v.MountDevice != "/dev/loop3" {
		t.Fatal("real mount tuple refused", err)
	}
	for _, v := range []string{string(mount) + string(mount), strings.Replace(string(mount), "noexec", "exec", 1), strings.Replace(string(mount), "7:3", "8:3", 1), strings.Replace(string(mount), "/dev/loop3", "/dev/loop4", 1), string(mount) + "13 12 7:4 / /var/lib/cloud8021x/collector/queue rw - ext4 /dev/loop4 rw\n"} {
		if _, err := parseControlCollector([]byte(v)); err == nil {
			t.Fatal("unsafe mount accepted")
		}
	}
	pin := strings.Repeat("a", 64)
	state := []byte(`{"schema":1,"seed_sha256":"` + pin + `","peers":{},"events":[],"batches":[],"commands":{},"submission_uncertain":false,"inventory_error":false,"intake_unavailable":true,"secrets":{}}`)
	if v, err := parseControlIntake(state, pin); err != nil || !v {
		t.Fatal("actual intake state refused", err)
	}
	for _, v := range []string{strings.Replace(string(state), "intake_unavailable", "Intake_Unavailable", 1), strings.Replace(string(state), "true", "null", 1), strings.Replace(string(state), pin, strings.Repeat("b", 64), 1), string(state) + " {}"} {
		if _, err := parseControlIntake([]byte(v), pin); err == nil {
			t.Fatal("unbound intake accepted")
		}
	}
	r := recordRequest(1, "probe-active-pair")
	services := map[string]controlServiceAuthority{}
	for _, name := range controlShippingUnits {
		_, authority := controlShippingFixture(t, name)
		services[name] = authority
	}
	raw := recordJSON(t, controlProbeInput{Schema: 1, RequestBytes: recordJSON(t, r), ConfigSHA256: pin, Services: services})
	if _, err := decodeControlProbeInput(raw, "task11-green-primary", pin, pin); err != nil {
		t.Fatal("actual request/config association refused", err)
	}
	if _, err := decodeControlProbeInput(raw, "task11-blue-primary", pin, pin); err == nil {
		t.Fatal("original source probed as active green")
	}
}
func TestScenarioControlsCleanupRequiresBothActualCases(t *testing.T) {
	e, r, f := controlFixture("probe-owned-cleanup")
	for _, kind := range []string{"deadline", "helper-death"} {
		f.cleanup.Cases = append(f.cleanup.Cases, sc.CleanupCase{Kind: kind, SentinelObservedAlive: true, SentinelRetired: true, Processes: []sc.ProcessObservation{{HostPID: 200, StartTicks: 12, ControlGroup: "/system.slice/task11-acceptance.service/operation-" + strings.Repeat("a", 32), Retired: true}, {HostPID: 201, StartTicks: 13, ControlGroup: "/system.slice/task11-acceptance.service/operation-" + strings.Repeat("a", 32), Retired: true}}})
	}
	if v, err := scenarioControlWith(context.Background(), e, r, f); err != nil || v.Cleanup == nil {
		t.Fatal("measured cleanup refused", err)
	}
	f.cleanup.Cases[0].SentinelObservedAlive = false
	if _, err := scenarioControlWith(context.Background(), e, r, f); err == nil {
		t.Fatal("unobserved sentinel accepted")
	}
}

func TestScenarioControlsShippingGuardedUnits(t *testing.T) {
	for _, name := range []string{"cloud-8021x.service", "freeradius.service", "datadog-agent.service"} {
		t.Run(name, func(t *testing.T) {
			fragment := "/etc/systemd/system/" + name
			drops := "/etc/systemd/system/" + name + ".d/parallel.conf"
			if name == "freeradius.service" {
				fragment = "/usr/lib/systemd/system/" + name
				drops = "/etc/systemd/system/" + name + ".d/cloud-8021x.conf " + drops
			}
			if name == "datadog-agent.service" {
				drops = "/etc/systemd/system/" + name + ".d/cloud-8021x.conf " + drops
			}
			raw := []byte("Id=" + name + "\nLoadState=loaded\nActiveState=active\nSubState=running\nMainPID=123\nControlGroup=/system.slice/" + name + "\nFragmentPath=" + fragment + "\nDropInPaths=" + drops + "\n")
			if _, err := parseControlProperties(raw, name); err != nil {
				t.Fatal("actual shipping fragment/dropins refused", err)
			}
		})
	}
}

func controlShippingFixture(t *testing.T, name string) (map[string][]byte, controlServiceAuthority) {
	t.Helper()
	rendered, err := systemd.Render()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range host.ParallelPassiveFiles() {
		rendered[f.Path] = f.Data
	}
	if name == "freeradius.service" {
		rendered["/usr/lib/systemd/system/freeradius.service"] = []byte("independently authenticated package fragment")
	}
	fragment := "/etc/systemd/system/" + name
	if name == "freeradius.service" {
		fragment = "/usr/lib/systemd/system/" + name
	}
	paths := []string{fragment, "/etc/systemd/system/" + name + ".d/parallel.conf"}
	if name == "freeradius.service" || name == "datadog-agent.service" {
		paths = append(paths, "/etc/systemd/system/"+name+".d/cloud-8021x.conf")
	}
	files := map[string][]byte{}
	authority := controlServiceAuthority{ExecutableSHA256: strings.Repeat("a", 64), Files: map[string]string{}}
	for _, path := range paths {
		raw, ok := rendered[path]
		if !ok {
			t.Fatal(path)
		}
		files[path] = raw
		authority.Files[path] = adoption.Digest(raw)
	}
	return files, authority
}
func TestScenarioControlsShippingAuthority(t *testing.T) {
	for _, name := range []string{"cloud-8021x.service", "freeradius.service", "step-ca.service", "step-ca-rsa.service", "datadog-agent.service", "datadog-agent-ddot.service"} {
		t.Run(name, func(t *testing.T) {
			files, authority := controlShippingFixture(t, name)
			if err := validateControlShipping(name, authority.ExecutableSHA256, files, authority); err != nil {
				t.Fatal("exact independent shipping authority refused", err)
			}
			t.Run("foreign-executable", func(t *testing.T) {
				if validateControlShipping(name, strings.Repeat("b", 64), files, authority) == nil {
					t.Fatal("foreign live executable accepted under shipping unit")
				}
			})
			for path := range files {
				t.Run("changed-"+path, func(t *testing.T) {
					changed := maps.Clone(files)
					changed[path] = []byte("[Service]\nExecStart=/usr/bin/sleep infinity\n")
					if validateControlShipping(name, authority.ExecutableSHA256, changed, authority) == nil {
						t.Fatal("changed protected unit content accepted")
					}
				})
			}
			t.Run("missing-authority", func(t *testing.T) {
				if validateControlShipping(name, authority.ExecutableSHA256, files, controlServiceAuthority{}) == nil {
					t.Fatal("missing independent shipping authority accepted")
				}
			})
			t.Run("extra-unit-file", func(t *testing.T) {
				changed := maps.Clone(files)
				changed["/run/systemd/system/foreign.conf"] = []byte("unexpected")
				if validateControlShipping(name, authority.ExecutableSHA256, changed, authority) == nil {
					t.Fatal("extra unit file accepted")
				}
			})
		})
	}
}
func TestScenarioControlsCrossPIDNamespaceBinding(t *testing.T) {
	raw := []byte("Name:\thelper\nPid:\t300\nPPid:\t200\nNSpid:\t300\t23\n")
	if validateControlNamespace(raw, 300, 23, 900, 900, 800) != nil {
		t.Fatal("actual separate namespace mapping refused")
	}
	for name, v := range map[string]struct {
		raw                     []byte
		host, local             int
		expected, actual, outer uint64
	}{
		"outer-namespace":      {raw, 300, 23, 800, 800, 800},
		"wrong-node-namespace": {raw, 300, 23, 900, 901, 800},
		"missing-namespace":    {raw, 300, 23, 900, 0, 800},
		"wrong-local-pid":      {raw, 300, 24, 900, 900, 800},
		"wrong-host-pid":       {raw, 301, 23, 900, 900, 800},
		"same-level":           {[]byte("Pid:\t300\nNSpid:\t300\n"), 300, 300, 900, 900, 800},
		"duplicate-mapping":    {append(append([]byte{}, raw...), []byte("NSpid:\t300\t23\n")...), 300, 23, 900, 900, 800},
		"leading-zero":         {[]byte("Pid:\t300\nNSpid:\t300\t023\n"), 300, 23, 900, 900, 800},
	} {
		t.Run(name, func(t *testing.T) {
			if validateControlNamespace(v.raw, v.host, v.local, v.expected, v.actual, v.outer) == nil {
				t.Fatal("unproven cross-PID namespace identity accepted")
			}
		})
	}
}

func controlTestDeb(t *testing.T, binary []byte, corrupt bool) string {
	t.Helper()
	var tarBytes bytes.Buffer
	tw := tar.NewWriter(&tarBytes)
	for _, name := range []string{"./", "./usr/", "./usr/bin/", "./usr/lib/", "./usr/lib/systemd/", "./usr/lib/systemd/system/"} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0755, Typeflag: tar.TypeDir}); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"./usr/bin/step-ca", "./usr/lib/systemd/system/freeradius.service"} {
		raw := binary
		if name != "./usr/bin/step-ca" {
			raw = []byte("exact pinned package unit")
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: int64(len(raw)), Uid: 0, Gid: 0, Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(tarBytes.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	var deb bytes.Buffer
	deb.WriteString("!<arch>\n")
	for _, part := range []struct {
		name string
		raw  []byte
	}{{"debian-binary", []byte("2.0\n")}, {"control.tar.gz", []byte("opaque control")}, {"data.tar.gz", compressed.Bytes()}} {
		fmt.Fprintf(&deb, "%-16s%-12d%-6d%-6d%-8o%-10d`\n", part.name+"/", 0, 0, 0, 0644, len(part.raw))
		deb.Write(part.raw)
		if len(part.raw)%2 != 0 {
			deb.WriteByte('\n')
		}
	}
	raw := deb.Bytes()
	if corrupt {
		raw[0] = '?'
	}
	path := filepath.Join(recordFixture(t), "pinned.deb")
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestScenarioControlsDeriveArchiveELF(t *testing.T) {
	binary := []byte("\x7fELFpublic shipping bytes")
	f, err := os.Open(controlTestDeb(t, binary, false))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	section, kind, err := controlDebData(f)
	if err != nil || kind != "gz" {
		t.Fatal("authenticated archive layout refused", kind, err)
	}
	gz, err := gzip.NewReader(section)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gz.Close() }()
	paths := []string{"/usr/bin/step-ca", "/usr/lib/systemd/system/freeradius.service"}
	got, err := controlTarDigests(gz, paths)
	if err != nil || got[paths[0]] != adoption.Digest(binary) || got[paths[1]] != adoption.Digest([]byte("exact pinned package unit")) {
		t.Fatal("exact package bytes did not produce expected independent SHA", err)
	}
	bad, err := os.Open(controlTestDeb(t, binary, true))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bad.Close() }()
	if _, _, err := controlDebData(bad); err == nil {
		t.Fatal("unrecognized archive accepted")
	}
}
func TestScenarioControlsPackageProjectionRejectsAliasesAndMissing(t *testing.T) {
	for _, kind := range []string{"duplicate", "hardlink", "alias", "missing", "wrong-owner", "writable", "not-elf"} {
		t.Run(kind, func(t *testing.T) {
			var raw bytes.Buffer
			tw := tar.NewWriter(&raw)
			body := []byte("\x7fELFpublic shipping bytes")
			name := "./usr/bin/step-ca"
			h := tar.Header{Name: name, Mode: 0755, Size: int64(len(body)), Typeflag: tar.TypeReg}
			switch kind {
			case "hardlink":
				h.Typeflag = tar.TypeLink
				h.Linkname = name
				h.Size = 0
			case "alias":
				h.Name = "./usr/bin/../bin/step-ca"
			case "missing":
				h.Name = "./usr/bin/other"
			case "wrong-owner":
				h.Uid = 1
			case "writable":
				h.Mode = 0775
			case "not-elf":
				body = []byte("foreign script")
				h.Size = int64(len(body))
			}
			if err := tw.WriteHeader(&h); err != nil {
				t.Fatal(err)
			}
			if h.Size > 0 {
				if _, err := tw.Write(body); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "duplicate" {
				if err := tw.WriteHeader(&h); err != nil {
					t.Fatal(err)
				}
				if _, err := tw.Write(body); err != nil {
					t.Fatal(err)
				}
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := controlTarDigests(bytes.NewReader(raw.Bytes()), []string{"/usr/bin/step-ca"}); err == nil {
				t.Fatal("unproven archived shipping identity accepted")
			}
		})
	}
	// The parser must propagate source truncation instead of turning it into absence.
	if _, err := controlTarDigests(io.LimitReader(bytes.NewReader([]byte("incomplete")), 2), []string{"/usr/bin/step-ca"}); err == nil {
		t.Fatal("truncated source accepted")
	}
}

func TestScenarioControlsAuthorityRawPinAndPrivateClosure(t *testing.T) {
	pin := strings.Repeat("a", 64)
	plan := recordJSON(t, map[string]any{"Schema": 1, "PackageManifestSHA256": pin, "LowerManifestSHA256": pin})
	if packages, lower, err := controlPlanAuthority(plan, adoption.Digest(plan)); err != nil || packages != pin || lower != pin {
		t.Fatal("original exact plan authority refused", err)
	}
	if _, _, err := controlPlanAuthority(append(append([]byte{}, plan...), ' '), adoption.Digest(plan)); err == nil {
		t.Fatal("substituted raw plan accepted")
	}
	lower := recordJSON(t, map[string]any{"Schema": 1, "Entries": []map[string]any{{"Path": "/usr/bin/xz", "Kind": "file", "SHA256": pin, "Mode": 0755, "Bytes": 100, "Target": ""}}})
	if got, err := controlLowerXZ(lower, adoption.Digest(lower)); err != nil || got != pin {
		t.Fatal("exact lower-derived decoder identity refused", err)
	}
	if _, err := controlLowerXZ(lower, strings.Repeat("b", 64)); err == nil {
		t.Fatal("unbound lower source accepted")
	}
	services := map[string]controlServiceAuthority{}
	for _, name := range controlShippingUnits {
		_, authority := controlShippingFixture(t, name)
		services[name] = authority
	}
	request := recordRequest(1, "probe-active-pair")
	raw := recordJSON(t, controlProbeInput{Schema: 1, RequestBytes: recordJSON(t, request), ConfigSHA256: pin, Services: services})
	if got, err := controlDecodeServices(raw); err != nil || len(got) != 6 {
		t.Fatal("exact closed package-derived authorities refused", err)
	}
	for _, bad := range [][]byte{
		[]byte(strings.Replace(string(raw), "\"executable_sha256\"", "\"Executable_SHA256\"", 1)),
		[]byte(strings.Replace(string(raw), "\"services\"", "\"Services\"", 1)),
		[]byte(strings.Replace(string(raw), "cloud-8021x.service", "foreign.service", 1)),
		[]byte(strings.Replace(string(raw), "/etc/systemd/system/step-ca.service", "/run/systemd/system/step-ca.service", 1)),
	} {
		if _, err := controlDecodeServices(bad); err == nil {
			t.Fatal("unbound/aliased service authority accepted")
		}
	}
}

func TestScenarioControlsDecoderCompletionPrecedesCleanup(t *testing.T) {
	done := make(chan error, 1)
	done <- nil
	killed := false
	if err := controlDecoderWait(context.Background(), done, false, func() error { killed = true; return nil }); err != nil || killed {
		t.Fatal("healthy decoder was killed before its actual completion", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	failed := make(chan error, 1)
	original := errors.New("original decoder failure")
	calls := 0
	if err := controlDecoderWait(ctx, failed, true, func() error { calls++; failed <- original; return nil }); !errors.Is(err, original) || calls != 1 {
		t.Fatal("failed decoder completion was lost or repeated", err, calls)
	}
}

// These public parser fixtures are synthetic; their pins establish only local
// archive selection semantics, never installed package or service proof.
func TestScenarioControlsPackageManifestAuthority(t *testing.T) {
	pin := strings.Repeat("a", 64)
	artifacts := []host.Artifact{
		{Name: "freeradius", Version: host.RadiusVersion, Architecture: "arm64", SHA256: pin},
		{Name: "step-ca", Version: host.StepCAVersion, Architecture: "arm64", SHA256: pin},
		{Name: "datadog-agent", Version: host.MonitoringVersion, Architecture: "arm64", SHA256: pin},
		{Name: "datadog-agent-ddot", Version: host.MonitoringVersion, Architecture: "arm64", SHA256: pin},
	}
	for i := 4; i < 62; i++ {
		artifacts = append(artifacts, host.Artifact{Name: fmt.Sprintf("synthetic-unselected-%d", i), Version: "1", Architecture: "all", SHA256: pin})
	}
	fixture := func(a []host.Artifact) []byte {
		return recordJSON(t, map[string]any{"schema": 1, "architecture": "arm64", "collector_sha256": pin, "artifacts": a})
	}
	raw := fixture(artifacts)
	got, err := controlPackagePins(raw, adoption.Digest(raw))
	if err != nil || len(got) != 4 || got["step-ca"] != artifacts[1] || got["datadog-agent-ddot"] != artifacts[3] {
		t.Fatal("original pinned service archives refused", err)
	}
	if _, err := controlPackagePins(raw, strings.Repeat("b", 64)); err == nil {
		t.Fatal("unbound raw package manifest accepted")
	}
	for _, kind := range []string{"missing", "duplicate", "version", "architecture", "digest", "top-alias", "field-alias"} {
		t.Run(kind, func(t *testing.T) {
			a := append([]host.Artifact(nil), artifacts...)
			switch kind {
			case "missing":
				a = a[1:]
			case "duplicate":
				a[4] = a[0]
			case "version":
				a[1].Version = "foreign"
			case "architecture":
				a[1].Architecture = "amd64"
			case "digest":
				a[1].SHA256 = strings.Repeat("A", 64)
			}
			bad := fixture(a)
			if kind == "top-alias" {
				bad = []byte(strings.Replace(string(bad), `"architecture"`, `"Architecture"`, 1))
			}
			if kind == "field-alias" {
				bad = []byte(strings.Replace(string(bad), `"name"`, `"Name"`, 1))
			}
			if _, err := controlPackagePins(bad, adoption.Digest(bad)); err == nil {
				t.Fatal("substituted service archive authority accepted")
			}
		})
	}
}
