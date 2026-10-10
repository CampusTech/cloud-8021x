package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

//go:embed dev-trigger-activators.json
var triggerActivators []byte

const baselineStatusSHA = "1f26ef9db373f957fe215b06d691979a5c5dbd97b4da2318cd157e117329767c"
const approvedLockSHA = "ac9c459fbc700c11017ae8159a1153883051c0b79d647f9087688796a2f247d0"
const interruptedBegin = "2026-10-09 05:18:00"
const interruptedEnd = "2026-10-09 05:23:00"

type packageIdentity struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
}
type packageState struct {
	packageIdentity
	Status  string
	Pending string
	Awaited string
}
type prerequisiteEvidence struct {
	Baseline      map[string]packageState
	Approved      map[string]packageIdentity
	Current       map[string]packageState
	Activators    map[string]packageIdentity
	SavedBaseline []byte
	DPKGLog       string
	Audit         []byte
	Final         bool
}

func parsePackageStatus(data []byte) (map[string]packageState, error) {
	result := map[string]packageState{}
	for _, paragraph := range strings.Split(strings.TrimSpace(string(data)), "\n\n") {
		fields := map[string]string{}
		for _, line := range strings.Split(paragraph, "\n") {
			if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
				continue
			}
			key, value, ok := strings.Cut(line, ":")
			if !ok || key == "" {
				return nil, errors.New("malformed dpkg status")
			}
			if _, exists := fields[key]; exists {
				return nil, errors.New("duplicate dpkg field")
			}
			fields[key] = strings.TrimPrefix(value, " ")
		}
		p := packageState{packageIdentity: packageIdentity{Name: fields["Package"], Version: fields["Version"], Architecture: fields["Architecture"]}, Status: fields["Status"], Pending: strings.Join(strings.Fields(fields["Triggers-Pending"]), " "), Awaited: strings.Join(strings.Fields(fields["Triggers-Awaited"]), " ")}
		if p.Name == "" || p.Version == "" || p.Architecture == "" || p.Status == "" {
			return nil, errors.New("incomplete dpkg identity")
		}
		if _, exists := result[p.Name]; exists {
			return nil, errors.New("duplicate package")
		}
		result[p.Name] = p
	}
	return result, nil
}

const queryPackageFormat = "Package: ${Package}\nVersion: ${Version}\nArchitecture: ${Architecture}\nStatus: ${Status}\nTriggers-Pending: ${Triggers-Pending}\nTriggers-Awaited: ${Triggers-Awaited}\n\n"

type packageQueryOutput struct {
	buffer bytes.Buffer
	limit  int
}

func (out *packageQueryOutput) Len() int      { return out.buffer.Len() }
func (out *packageQueryOutput) Bytes() []byte { return out.buffer.Bytes() }
func (out *packageQueryOutput) Write(data []byte) (int, error) {
	if len(data) > out.limit-out.Len() {
		return 0, errors.New("dpkg-query output exceeds bound")
	}
	return out.buffer.Write(data)
}

// dpkg-query merges interrupted updates journals. Reading admindir/status is
// never authoritative for a live current/final gate. Every call executes a
// fresh bounded query; the raw pinned status is only the immutable baseline.
func loadCurrentPackageState(admindir string) (map[string]packageState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/dpkg-query", "--admindir="+admindir, "-W", "-f="+queryPackageFormat)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	stdout := &packageQueryOutput{limit: 4 << 20}
	stderr := &packageQueryOutput{limit: 64 << 10}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("authoritative dpkg-query failed: %w", err)
	}
	if stderr.Len() != 0 {
		return nil, errors.New("authoritative dpkg-query reported diagnostics")
	}
	return parsePackageStatus(stdout.Bytes())
}
func samePackage(a, b packageIdentity) bool {
	return a.Name == b.Name && a.Version == b.Version && a.Architecture == b.Architecture
}
func baselineTSV(base map[string]packageState) []byte {
	lines := make([]string, 0, len(base))
	for _, p := range base {
		lines = append(lines, p.Name+"\t"+p.Version)
	}
	sort.Strings(lines)
	return []byte(strings.Join(lines, "\n") + "\n")
}

// validateInterruptedLog allows only the original bounded v4 installation, not
// any later arbitrary package transaction. It requires an approved activator's
// actual installation to precede the exact baseline trigger transition.
func validateInterruptedLog(e prerequisiteEvidence) error {
	activated, transition, started := false, false, false
	previousStamp := ""
	for _, line := range strings.Split(e.DPKGLog, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if len(line) < 20 {
			return errors.New("malformed dpkg log")
		}
		stamp := line[:19]
		if _, err := time.Parse("2006-01-02 15:04:05", stamp); err != nil {
			return errors.New("invalid dpkg log timestamp")
		}
		if stamp < interruptedBegin {
			continue
		}
		if stamp > interruptedEnd {
			return errors.New("package activity outside owned interrupted attempt")
		}
		if stamp < previousStamp {
			return errors.New("reordered interrupted dpkg events")
		}
		previousStamp = stamp
		f := strings.Fields(line[20:])
		if len(f) == 0 {
			return errors.New("empty dpkg event")
		}
		if len(f) == 3 && f[0] == "startup" && f[1] == "archives" && f[2] == "install" {
			if started {
				return errors.New("multiple package transactions")
			}
			started = true
			continue
		}
		if !started {
			return errors.New("missing owned install start")
		}
		if len(f) == 4 && f[0] == "install" {
			name, arch, ok := strings.Cut(f[1], ":")
			p, exists := e.Approved[name]
			if !ok || !exists || arch != p.Architecture || f[2] != "<none>" || f[3] != p.Version {
				return errors.New("unapproved install in interrupted log")
			}
			if a, exists := e.Activators[name]; exists && samePackage(a, p) {
				current, present := e.Current[name]
				if present && samePackage(current.packageIdentity, p) {
					activated = true
				}
			}
			continue
		}
		if len(f) == 4 && f[0] == "status" {
			name, arch, ok := strings.Cut(f[2], ":")
			if !ok {
				return errors.New("unqualified logged package")
			}
			if p, exists := e.Baseline[name]; exists {
				if arch != p.Architecture || f[3] != p.Version {
					return errors.New("baseline log identity changed")
				}
				if f[1] == "installed" {
					continue
				}
				if name == "libc-bin" && f[1] == "triggers-pending" && activated {
					transition = true
					continue
				}
				return errors.New("unapproved baseline status transition")
			}
			p, exists := e.Approved[name]
			if !exists || arch != p.Architecture || f[3] != p.Version {
				return errors.New("unapproved package log identity")
			}
			switch f[1] {
			case "half-installed", "unpacked", "half-configured", "installed", "triggers-pending", "triggers-awaited":
				continue
			}
		}
		return errors.New("unapproved dpkg event")
	}
	if !activated || !transition {
		return errors.New("missing approved ldconfig trigger lineage")
	}
	return nil
}

func verifyPrerequisites(e prerequisiteEvidence) error {
	if len(e.Baseline) == 0 || len(e.Approved) == 0 {
		return errors.New("empty approved inventory")
	}
	for name, p := range e.Baseline {
		if p.Status != "install ok installed" || p.Pending != "" || p.Awaited != "" {
			return errors.New("baseline was not clean")
		}
		if _, overlap := e.Approved[name]; overlap {
			return errors.New("approved set replaces baseline")
		}
	}
	interrupted := false
	for name, p := range e.Current {
		if baseline, ok := e.Baseline[name]; ok {
			if !samePackage(p.packageIdentity, baseline.packageIdentity) {
				return fmt.Errorf("baseline identity changed: %s", name)
			}
			if p.Status == "install ok installed" && p.Pending == "" && p.Awaited == "" {
				continue
			}
			// No baseline awaited links are currently proved by the retained attempt.
			// In particular an arbitrary triggers-awaited status is never sufficient.
			if !e.Final && name == "libc-bin" && p.Status == "install ok triggers-pending" && p.Pending == "ldconfig" && p.Awaited == "" {
				interrupted = true
				continue
			}
			return fmt.Errorf("unapproved baseline state: %s", name)
		}
		approved, ok := e.Approved[name]
		if !ok || !samePackage(p.packageIdentity, approved) {
			return fmt.Errorf("unapproved extra or replacement: %s", name)
		}
		if e.Final {
			if p.Status != "install ok installed" || p.Pending != "" || p.Awaited != "" {
				return fmt.Errorf("development package not fully installed: %s", name)
			}
		} else {
			// Only these states can have resulted from the observed unpack-only v4.
			if p.Status != "install ok unpacked" && p.Status != "install ok half-installed" && p.Status != "install reinstreq half-installed" {
				return fmt.Errorf("unproved interrupted development state: %s", name)
			}
			if p.Pending != "" || p.Awaited != "" {
				return errors.New("unproved development trigger state")
			}
			interrupted = true
		}
	}
	for name := range e.Baseline {
		if _, ok := e.Current[name]; !ok {
			return fmt.Errorf("missing baseline package: %s", name)
		}
	}
	if e.Final {
		for name := range e.Approved {
			if _, ok := e.Current[name]; !ok {
				return fmt.Errorf("missing development package: %s", name)
			}
		}
		if len(e.Audit) != 0 {
			return errors.New("dpkg audit is not empty")
		}
		return nil
	}
	if interrupted {
		if !bytes.Equal(e.SavedBaseline, baselineTSV(e.Baseline)) {
			return errors.New("missing exact pre-install baseline evidence")
		}
		if err := validateInterruptedLog(e); err != nil {
			return err
		}
		found := false
		for name, a := range e.Activators {
			if p, ok := e.Current[name]; ok && samePackage(p.packageIdentity, a) {
				found = true
			}
		}
		if !found {
			return errors.New("approved trigger activator is not present")
		}
	}
	return nil
}

func boundedFixtureFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("unsafe evidence file")
	}
	return os.ReadFile(path)
}
func verifyApprovedArchives(media string, packages []packageIdentity) error {
	entries, err := os.ReadDir(filepath.Join(media, "archives"))
	if err != nil {
		return err
	}
	expected := map[string]bool{"sha256sums": true}
	for i := range packages {
		expected[fmt.Sprintf("p%03d.deb", i)] = true
	}
	if len(entries) != len(expected) {
		return errors.New("unexpected archive directory entry count")
	}
	for _, entry := range entries {
		if !expected[entry.Name()] || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("unapproved archive directory entry")
		}
	}
	for i, p := range packages {
		path := filepath.Join(media, "archives", fmt.Sprintf("p%03d.deb", i))
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || p.Size <= 0 || info.Size() != p.Size {
			return errors.New("approved archive size/type mismatch")
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		h := sha256.New()
		_, copyErr := io.Copy(h, f)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if hex.EncodeToString(h.Sum(nil)) != p.SHA256 {
			return errors.New("approved archive digest mismatch")
		}
	}
	return nil
}
func checkPinned(data []byte, want string) error {
	got := sha256.Sum256(data)
	if hex.EncodeToString(got[:]) != want {
		return errors.New("pinned fixture identity mismatch")
	}
	return nil
}
func prerequisiteCommand() *cobra.Command {
	var media, root string
	var final bool
	cmd := &cobra.Command{Use: "prerequisites", Short: "Verify exact owned offline prerequisite state without modifying it", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		marker, err := read("/etc/cloud8021x-task11-fixture")
		if err != nil || marker != "synthetic-only-v1" || os.Geteuid() != 0 {
			return errors.New("owned root guest required")
		}
		if media != "/run/task11-media" || root != "/var/lib/cloud8021x-task11" {
			return errors.New("fixed owned evidence paths required")
		}
		baseBytes, err := boundedFixtureFile(filepath.Join(media, "base.txt"), 2<<20)
		if err != nil {
			return err
		}
		if err = checkPinned(baseBytes, baselineStatusSHA); err != nil {
			return err
		}
		baseline, err := parsePackageStatus(baseBytes)
		if err != nil {
			return err
		}
		lockBytes, err := boundedFixtureFile(filepath.Join(media, "dev.txt"), 1<<20)
		if err != nil {
			return err
		}
		if err = checkPinned(lockBytes, approvedLockSHA); err != nil {
			return err
		}
		var lock struct {
			Packages []packageIdentity `json:"packages"`
		}
		if err = json.Unmarshal(lockBytes, &lock); err != nil {
			return err
		}
		var rules struct {
			LockSHA  string            `json:"lock_sha256"`
			Packages []packageIdentity `json:"packages"`
		}
		if err = json.Unmarshal(triggerActivators, &rules); err != nil {
			return err
		}
		if len(baseline) != 321 || len(lock.Packages) != 26 || rules.LockSHA != approvedLockSHA {
			return errors.New("fixture inventory boundary mismatch")
		}
		if err = verifyApprovedArchives(media, lock.Packages); err != nil {
			return err
		}
		e := prerequisiteEvidence{Baseline: baseline, Approved: map[string]packageIdentity{}, Activators: map[string]packageIdentity{}, Final: final}
		for _, p := range lock.Packages {
			if _, ok := e.Approved[p.Name]; ok {
				return errors.New("duplicate approved package")
			}
			e.Approved[p.Name] = p
		}
		for _, p := range rules.Packages {
			a, ok := e.Approved[p.Name]
			if !ok || !samePackage(a, p) || a.SHA256 != p.SHA256 {
				return errors.New("trigger declaration not bound to approved archive")
			}
			e.Activators[p.Name] = p
		}
		e.Current, err = loadCurrentPackageState("/var/lib/dpkg")
		if err != nil {
			return err
		}
		e.SavedBaseline, err = boundedFixtureFile(filepath.Join(root, "live-base.tsv"), 1<<20)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if final {
			e.Audit, err = boundedFixtureFile(filepath.Join(root, "dpkg-audit"), 1<<20)
		} else {
			var log []byte
			log, err = boundedFixtureFile("/var/log/dpkg.log", 8<<20)
			// A pristine image has no prior transaction to document. Missing
			// history is permitted only for the exact clean baseline, never
			// as evidence for any interrupted or additional package state.
			if errors.Is(err, os.ErrNotExist) {
				clean := len(e.Current) == len(e.Baseline)
				for name, want := range e.Baseline {
					got, ok := e.Current[name]
					if !ok || !samePackage(got.packageIdentity, want.packageIdentity) || got.Status != "install ok installed" || got.Pending != "" || got.Awaited != "" {
						clean = false
						break
					}
				}
				if clean {
					err = nil
				}
			}
			e.DPKGLog = string(log)
		}
		if err != nil {
			return err
		}
		return verifyPrerequisites(e)
	}}
	cmd.Flags().StringVar(&media, "media", "/run/task11-media", "Fixed read-only evidence seed")
	cmd.Flags().StringVar(&root, "fixture-root", "/var/lib/cloud8021x-task11", "Fixed owned interrupted state")
	cmd.Flags().BoolVar(&final, "final", false, "Require all baseline and approved packages fully installed and empty audit")
	return cmd
}
