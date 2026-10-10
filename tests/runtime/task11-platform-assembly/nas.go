package main

import (
	"errors"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	seed "github.com/CampusTech/cloud-8021x/tests/runtime/task11-assembly-seed/contract"
)

const nasRoot = platformRoot + "/aux/nas"
const nasProc = nasRoot + "/proc"

type nasHelperBinding struct {
	Source pin
	Target string
}
type nasProcFacts struct {
	Device                                  string
	ProcFS, ReadOnly, NoSuid, NoDev, NoExec bool
	PIDNamespace, OuterPIDNamespace         uint64
}
type nasMount struct {
	device, root, target, filesystem, source string
	options                                  []string
}

func nasHelperBindings(p plan) ([]nasHelperBinding, error) {
	var out []nasHelperBinding
	for _, name := range []string{"task11-systemd-fixture", "task11-scenarios"} {
		source := p.Helpers[name]
		if source.Path != publicRoot+"/"+name || !seed.IsSHA(source.SHA256) {
			return nil, errors.New("fixed NAS helper pin absent")
		}
		out = append(out, nasHelperBinding{source, nasRoot + "/usr/local/libexec/" + name})
	}
	return out, nil
}
func nasProcArguments() []string {
	return []string{"--no-canonicalize", "--types", "proc", "--options", "ro,nosuid,nodev,noexec", "proc", nasProc}
}

// Only these fixed targets are inspected. Actual observations remain separate
// from the generated inventory; this parser does not manufacture readiness.
func nasTargetMounts(raw []byte, target string) ([]nasMount, error) {
	if len(raw) == 0 || len(raw) > 4<<20 || (target != nasProc && target != nasRoot+"/usr/local/libexec/task11-systemd-fixture" && target != nasRoot+"/usr/local/libexec/task11-scenarios") {
		return nil, errors.New("bounded fixed NAS mount inventory required")
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) > 65536 {
		return nil, errors.New("NAS mount inventory exceeds bound")
	}
	var out []nasMount
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			return nil, errors.New("malformed actual mount inventory")
		}
		if strings.HasPrefix(fields[4], target+"/") {
			return nil, errors.New("unexpected NAS child mount refused")
		}
		if fields[4] != target {
			continue
		}
		dash := slices.Index(fields, "-")
		if dash < 6 || len(fields) != dash+4 || filepath.Clean(fields[3]) != fields[3] || !strings.HasPrefix(fields[3], "/") {
			return nil, errors.New("ambiguous NAS mount tuple")
		}
		device := strings.Split(fields[2], ":")
		if len(device) != 2 {
			return nil, errors.New("actual NAS device differs")
		}
		for _, value := range device {
			number, err := strconv.ParseUint(value, 10, 32)
			if err != nil || strconv.FormatUint(number, 10) != value {
				return nil, errors.New("noncanonical NAS device")
			}
		}
		opts := strings.Split(fields[5], ",")
		seen := map[string]bool{}
		for _, option := range opts {
			if option == "" || seen[option] {
				return nil, errors.New("ambiguous NAS mount options")
			}
			seen[option] = true
		}
		out = append(out, nasMount{fields[2], fields[3], fields[4], fields[dash+1], fields[dash+2], opts})
	}
	return out, nil
}
func requireNASProcAbsent(raw []byte) error {
	mounts, err := nasTargetMounts(raw, nasProc)
	if err != nil || len(mounts) != 0 {
		return errors.New("preexisting NAS proc mount refused; no implicit repair")
	}
	return nil
}
func validateNASProc(raw []byte, facts nasProcFacts) error {
	mounts, err := nasTargetMounts(raw, nasProc)
	if err != nil || len(mounts) != 1 || !facts.ProcFS || !facts.ReadOnly || !facts.NoSuid || !facts.NoDev || !facts.NoExec || facts.PIDNamespace == 0 || facts.PIDNamespace != facts.OuterPIDNamespace {
		return errors.New("actual NAS proc identity not proven")
	}
	m := mounts[0]
	if m.root != "/" || m.filesystem != "proc" || m.source != "proc" || m.device != facts.Device {
		return errors.New("foreign NAS proc mount refused")
	}
	for _, option := range []string{"ro", "nosuid", "nodev", "noexec"} {
		if !slices.Contains(m.options, option) {
			return errors.New("unsafe NAS proc options")
		}
	}
	for _, option := range []string{"rw", "suid", "dev", "exec"} {
		if slices.Contains(m.options, option) {
			return errors.New("conflicting NAS proc options")
		}
	}
	return nil
}
func validateNASHelperMount(raw []byte, target, device string) error {
	mounts, err := nasTargetMounts(raw, target)
	if err != nil || len(mounts) != 1 {
		return errors.New("actual NAS helper mount absent or ambiguous")
	}
	m := mounts[0]
	if m.device != device || m.root == "/" || !slices.Contains(m.options, "ro") || slices.Contains(m.options, "rw") {
		return errors.New("readonly retained NAS helper mount not proven")
	}
	return nil
}
