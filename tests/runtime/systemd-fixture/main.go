// systemd-fixture records real guest state. It never starts/stops services,
// creates receipts, edits product configuration, or fabricates reboot evidence.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var units = []string{"cloud-8021x.service", "freeradius.service", "step-ca.service", "step-ca-rsa.service", "cloud-8021x-renew.service", "cloud-8021x-renew.timer", "cloud-8021x-sources.service", "cloud-8021x-sources.timer", "datadog-agent.service", "datadog-agent-ddot.service", "var-lib-cloud8021x-collector.mount"}
var stateFiles = []string{"/usr/local/bin/cloud-8021x", "/etc/cloud-8021x/config.yaml", "/etc/cloud-8021x/ddot.yaml", "/etc/systemd/system/var-lib-cloud8021x-collector.mount"}

type snapshot struct {
	Schema     int                          `json:"schema"`
	Hostname   string                       `json:"hostname"`
	BootID     string                       `json:"boot_id"`
	Kernel     string                       `json:"kernel"`
	Namespaces map[string]string            `json:"namespaces"`
	Packages   string                       `json:"packages"`
	Routes4    string                       `json:"routes4"`
	Routes6    string                       `json:"routes6"`
	Listeners  string                       `json:"listeners"`
	Cgroup     string                       `json:"cgroup"`
	UnitState  map[string]map[string]string `json:"units"`
	FileHashes map[string]string            `json:"file_hashes"`
	Mount      string                       `json:"mount"`
	Loop       string                       `json:"loop"`
}

func command(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	if len(out) > 1<<20 {
		return "", errors.New("probe output limit")
	}
	return strings.TrimSpace(string(out)), nil
}
func read(path string) (string, error) {
	b, err := os.ReadFile(path)
	return strings.TrimSpace(string(b)), err
}
func audit(mode string) (snapshot, error) {
	s := snapshot{Schema: 1, Namespaces: map[string]string{}, UnitState: map[string]map[string]string{}, FileHashes: map[string]string{}}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return s, errors.New("root Linux fixture required")
	}
	marker, err := read("/etc/cloud8021x-task11-fixture")
	if err != nil || marker != "synthetic-only-v1" {
		return s, errors.New("not an enrolled development guest")
	}
	s.Hostname, err = os.Hostname()
	if err != nil || !strings.HasPrefix(s.Hostname, "task11-") {
		return s, errors.New("fixture hostname rejected")
	}
	pid1, err := read("/proc/1/comm")
	if err != nil || pid1 != "systemd" {
		return s, errors.New("real systemd PID1 required")
	}
	s.Kernel, err = command("uname", "-a")
	if err != nil {
		return s, err
	}
	if strings.Contains(strings.ToLower(s.Kernel), "orbstack") {
		return s, errors.New("shared OrbStack kernel cannot prove owned loop-device boundary")
	}
	s.BootID, err = read("/proc/sys/kernel/random/boot_id")
	if err != nil || len(s.BootID) != 36 {
		return s, errors.New("boot identity unavailable")
	}
	for _, kind := range []string{"pid", "mnt", "net", "uts", "user", "cgroup"} {
		s.Namespaces[kind], err = os.Readlink("/proc/1/ns/" + kind)
		if err != nil {
			return s, err
		}
	}
	s.Cgroup, err = read("/proc/1/cgroup")
	if err != nil {
		return s, err
	}
	fs, err := command("stat", "-fc", "%T", "/sys/fs/cgroup")
	if err != nil || fs != "cgroup2fs" {
		return s, errors.New("cgroup v2 required")
	}
	mounts, err := read("/proc/self/mountinfo")
	if err != nil {
		return s, err
	}
	for _, forbidden := range []string{"virtiofs", "/mnt/mac", "/Users/", "docker.sock"} {
		if strings.Contains(mounts, forbidden) {
			return s, errors.New("forbidden host/shared mount")
		}
	}
	s.Routes4, err = command("ip", "-4", "route", "show", "table", "all")
	if err != nil {
		return s, err
	}
	s.Routes6, err = command("ip", "-6", "route", "show", "table", "all")
	if err != nil {
		return s, err
	}
	for _, routes := range []string{s.Routes4, s.Routes6} {
		for _, line := range strings.Split(routes, "\n") {
			if strings.HasPrefix(line, "default ") {
				return s, errors.New("fixture must have no default route in any table")
			}
		}
	}
	s.Listeners, err = command("ss", "-H", "-lntup")
	if err != nil {
		return s, err
	}
	s.Packages, err = command("dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\n", "systemd", "sudo", "libc6", "libssl3t64", "perl-base")
	if err != nil {
		return s, err
	}
	for _, path := range stateFiles {
		b, err := os.ReadFile(path)
		if err != nil {
			return s, err
		}
		sum := sha256.Sum256(b)
		s.FileHashes[path] = hex.EncodeToString(sum[:])
	}
	for _, unit := range units {
		text, err := command("systemctl", "show", unit, "--property=LoadState,ActiveState,SubState,MainPID,ControlGroup,FragmentPath,ConditionResult,Result")
		if err != nil {
			return s, err
		}
		row := map[string]string{}
		for _, line := range strings.Split(text, "\n") {
			k, v, ok := strings.Cut(line, "=")
			if ok {
				row[k] = v
			}
		}
		if row["LoadState"] != "loaded" {
			return s, fmt.Errorf("required installed unit %s missing", unit)
		}
		if mode == "passive" && (row["ActiveState"] == "active" || (row["MainPID"] != "" && row["MainPID"] != "0")) {
			return s, fmt.Errorf("passive unit %s is running", unit)
		}
		if pid, err := strconv.Atoi(row["MainPID"]); err == nil && pid > 0 {
			executable, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
			if err != nil {
				return s, err
			}
			row["Executable"] = executable
			if strings.Contains(executable, "native-fixture") {
				return s, errors.New("substitute test process rejected")
			}
			row["ProcessCgroup"], err = read(fmt.Sprintf("/proc/%d/cgroup", pid))
			if err != nil || !strings.Contains(row["ProcessCgroup"], row["ControlGroup"]) {
				return s, errors.New("service cgroup evidence mismatch")
			}
		}
		s.UnitState[unit] = row
	}
	if mode == "active" {
		for _, unit := range []string{"cloud-8021x.service", "freeradius.service", "step-ca.service", "step-ca-rsa.service", "datadog-agent.service", "datadog-agent-ddot.service"} {
			r := s.UnitState[unit]
			if r["ActiveState"] != "active" || r["MainPID"] == "0" || r["MainPID"] == "" {
				return s, fmt.Errorf("installed service %s not active", unit)
			}
		}
		s.Mount, err = command("findmnt", "--noheadings", "--mountpoint", "/var/lib/cloud8021x/collector", "--output", "SOURCE,FSTYPE,OPTIONS")
		if err != nil {
			return s, err
		}
		parts := strings.Fields(s.Mount)
		if len(parts) != 3 || !strings.HasPrefix(parts[0], "/dev/loop") || parts[1] != "ext4" {
			return s, errors.New("collector is not a genuine loop-mounted ext4 filesystem")
		}
		options := "," + parts[2] + ","
		for _, opt := range []string{"nodev", "nosuid", "noexec"} {
			if !strings.Contains(options, ","+opt+",") {
				return s, errors.New("collector mount options changed")
			}
		}
		s.Loop, err = command("losetup", "--noheadings", "--output", "BACK-FILE", parts[0])
		if err != nil {
			return s, err
		}
		if s.Loop != "/var/lib/cloud-8021x-bootstrap/collector.ext4" {
			return s, errors.New("collector loop backing file changed")
		}
	}
	return s, nil
}
func compareReboot(before, after snapshot) error {
	if before.Schema != 1 || before.Hostname != after.Hostname || before.BootID == after.BootID {
		return errors.New("no genuine same-node reboot proved")
	}
	for path, digest := range before.FileHashes {
		if after.FileHashes[path] != digest {
			return fmt.Errorf("persistent artifact changed across reboot: %s", path)
		}
	}
	return nil
}
func main() {
	var mode, previous, output string
	cmd := &cobra.Command{Use: "systemd-fixture", SilenceUsage: true, RunE: func(_ *cobra.Command, _ []string) error {
		if mode != "active" && mode != "passive" {
			return errors.New("mode must be active or passive")
		}
		state, err := audit(mode)
		if err != nil {
			return err
		}
		if previous != "" {
			b, err := os.ReadFile(previous)
			if err != nil {
				return err
			}
			var before snapshot
			if json.Unmarshal(b, &before) != nil {
				return errors.New("invalid previous snapshot")
			}
			if err := compareReboot(before, state); err != nil {
				return err
			}
		}
		if !filepath.IsAbs(output) {
			return errors.New("absolute new evidence path required")
		}
		f, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		return json.NewEncoder(f).Encode(state)
	}}
	cmd.AddCommand(packetCommand(), prerequisiteCommand(), gptCommand(), gptVerifyCommand())
	cmd.Flags().StringVar(&mode, "mode", "passive", "expected installed service state")
	cmd.Flags().StringVar(&previous, "previous", "", "previous same-node snapshot for reboot comparison")
	cmd.Flags().StringVar(&output, "output", "", "new evidence JSON path")
	if err := cmd.Execute(); err != nil {
		logrus.WithError(err).Error("fixture audit failed")
		os.Exit(1)
	}
}
