package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func interruptedPrerequisites() prerequisiteEvidence {
	base := packageState{packageIdentity: packageIdentity{Name: "libc-bin", Version: "2.41-12+deb13u4", Architecture: "arm64"}, Status: "install ok installed"}
	library := packageIdentity{Name: "libgcrypt20", Version: "1.11.0-7+deb13u1", Architecture: "arm64"}
	pending := base
	pending.Status = "install ok triggers-pending"
	pending.Pending = "ldconfig"
	baseline := map[string]packageState{base.Name: base}
	return prerequisiteEvidence{Baseline: baseline, Approved: map[string]packageIdentity{library.Name: library}, Current: map[string]packageState{base.Name: pending, library.Name: {packageIdentity: library, Status: "install ok unpacked"}}, Activators: map[string]packageIdentity{library.Name: library}, SavedBaseline: baselineTSV(baseline), DPKGLog: "2026-10-09 05:20:30 startup archives install\n2026-10-09 05:20:31 install libgcrypt20:arm64 <none> 1.11.0-7+deb13u1\n2026-10-09 05:20:31 status half-installed libgcrypt20:arm64 1.11.0-7+deb13u1\n2026-10-09 05:20:31 status triggers-pending libc-bin:arm64 2.41-12+deb13u4\n2026-10-09 05:20:32 status unpacked libgcrypt20:arm64 1.11.0-7+deb13u1\n"}
}

// This case originally failed on the inline guard with the same libc-bin
// status reported by the real v5 VM. It now additionally requires actual log
// ordering, a pinned activator identity, exact saved baseline and trigger name.
func TestInterruptedApprovedLDConfigTriggerCanResume(t *testing.T) {
	if err := verifyPrerequisites(interruptedPrerequisites()); err != nil {
		t.Fatal(err)
	}
}
func TestPrerequisiteRecoveryRejectsUnrelatedState(t *testing.T) {
	cases := map[string]func(*prerequisiteEvidence){
		"baseline version": func(e *prerequisiteEvidence) {
			p := e.Current["libc-bin"]
			p.Version = "different"
			e.Current[p.Name] = p
		},
		"baseline architecture": func(e *prerequisiteEvidence) {
			p := e.Current["libc-bin"]
			p.Architecture = "amd64"
			e.Current[p.Name] = p
		},
		"missing baseline": func(e *prerequisiteEvidence) { delete(e.Current, "libc-bin") },
		"extra package": func(e *prerequisiteEvidence) {
			e.Current["curl"] = packageState{packageIdentity: packageIdentity{Name: "curl", Version: "1", Architecture: "arm64"}, Status: "install ok installed"}
		},
		"development version": func(e *prerequisiteEvidence) {
			p := e.Current["libgcrypt20"]
			p.Version = "different"
			e.Current[p.Name] = p
		},
		"development architecture": func(e *prerequisiteEvidence) {
			p := e.Current["libgcrypt20"]
			p.Architecture = "amd64"
			e.Current[p.Name] = p
		},
		"unproved configured development package": func(e *prerequisiteEvidence) {
			p := e.Current["libgcrypt20"]
			p.Status = "install ok installed"
			e.Current[p.Name] = p
		},
		"unrelated pending trigger": func(e *prerequisiteEvidence) {
			p := e.Current["libc-bin"]
			p.Pending = "unreviewed"
			e.Current[p.Name] = p
		},
		"extra pending trigger": func(e *prerequisiteEvidence) {
			p := e.Current["libc-bin"]
			p.Pending = "ldconfig other"
			e.Current[p.Name] = p
		},
		"awaited baseline": func(e *prerequisiteEvidence) {
			p := e.Current["libc-bin"]
			p.Status = "install ok triggers-awaited"
			p.Pending = ""
			p.Awaited = "other"
			e.Current[p.Name] = p
		},
		"half configured baseline": func(e *prerequisiteEvidence) {
			p := e.Current["libc-bin"]
			p.Status = "install ok half-configured"
			e.Current[p.Name] = p
		},
		"stale trigger on installed baseline": func(e *prerequisiteEvidence) {
			p := e.Current["libc-bin"]
			p.Status = "install ok installed"
			e.Current[p.Name] = p
		},
		"absent saved baseline":              func(e *prerequisiteEvidence) { e.SavedBaseline = nil },
		"changed saved baseline":             func(e *prerequisiteEvidence) { e.SavedBaseline = []byte("unrelated\n") },
		"no approved activation declaration": func(e *prerequisiteEvidence) { e.Activators = map[string]packageIdentity{} },
		"declaration identity mismatch": func(e *prerequisiteEvidence) {
			p := e.Activators["libgcrypt20"]
			p.Version = "wrong"
			e.Activators[p.Name] = p
		},
		"missing owned log": func(e *prerequisiteEvidence) { e.DPKGLog = "" },
		"later transaction": func(e *prerequisiteEvidence) { e.DPKGLog += "2026-10-09 05:30:00 startup archives install\n" },
		"replacement transaction": func(e *prerequisiteEvidence) {
			e.DPKGLog = strings.ReplaceAll(e.DPKGLog, "install libgcrypt20:arm64 <none>", "upgrade libgcrypt20:arm64 1.0")
		},
		"unapproved baseline trigger receiver": func(e *prerequisiteEvidence) {
			p := packageState{packageIdentity: packageIdentity{Name: "man-db", Version: "1", Architecture: "arm64"}, Status: "install ok installed"}
			e.Baseline[p.Name] = p
			p.Status = "install ok triggers-pending"
			p.Pending = "/usr/share/man"
			e.Current[p.Name] = p
			e.SavedBaseline = baselineTSV(e.Baseline)
		},
		"trigger before activator": func(e *prerequisiteEvidence) {
			e.DPKGLog = "2026-10-09 05:20:30 status triggers-pending libc-bin:arm64 2.41-12+deb13u4\n" + e.DPKGLog
		},
	}
	for name, modify := range cases {
		t.Run(name, func(t *testing.T) {
			e := interruptedPrerequisites()
			modify(&e)
			if err := verifyPrerequisites(e); err == nil {
				t.Fatal("unrelated or unproved state accepted")
			}
		})
	}
}
func TestPrerequisiteFinalGateRequiresEveryExactInstalledPackageAndEmptyAudit(t *testing.T) {
	complete := func() prerequisiteEvidence {
		e := interruptedPrerequisites()
		e.Final = true
		for name, p := range e.Current {
			p.Status = "install ok installed"
			p.Pending = ""
			p.Awaited = ""
			e.Current[name] = p
		}
		return e
	}
	if err := verifyPrerequisites(complete()); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"pending baseline", "pending development", "missing development", "audit bytes", "audit whitespace"} {
		t.Run(kind, func(t *testing.T) {
			e := complete()
			switch kind {
			case "pending baseline":
				p := e.Current["libc-bin"]
				p.Status = "install ok triggers-pending"
				p.Pending = "ldconfig"
				e.Current[p.Name] = p
			case "pending development":
				p := e.Current["libgcrypt20"]
				p.Status = "install ok unpacked"
				e.Current[p.Name] = p
			case "missing development":
				delete(e.Current, "libgcrypt20")
			case "audit bytes":
				e.Audit = []byte("incomplete package\n")
			case "audit whitespace":
				e.Audit = []byte("\n")
			}
			if err := verifyPrerequisites(e); err == nil {
				t.Fatal("incomplete final state accepted")
			}
		})
	}
}
func TestPrerequisiteCleanInitialState(t *testing.T) {
	e := interruptedPrerequisites()
	delete(e.Current, "libgcrypt20")
	e.Current["libc-bin"] = e.Baseline["libc-bin"]
	e.SavedBaseline = nil
	e.DPKGLog = ""
	if err := verifyPrerequisites(e); err != nil {
		t.Fatal(err)
	}
}
func TestPackageStatusParserPreservesArchitectureAndTriggerFields(t *testing.T) {
	text := "Package: libc-bin\nStatus: install ok triggers-pending\nArchitecture: arm64\nVersion: 2.41-12+deb13u4\nTriggers-Pending: ldconfig\nConffiles:\n /etc/test deadbeef\nDescription: test\n continuation: ignored\n"
	p, err := parsePackageStatus([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if p["libc-bin"].Architecture != "arm64" || p["libc-bin"].Pending != "ldconfig" {
		t.Fatal("identity or trigger lost")
	}
	for _, bad := range []string{text + "\n" + text, strings.Replace(text, "Version: 2.41-12+deb13u4\n", "", 1), text + "Architecture: amd64\n"} {
		if _, err := parsePackageStatus([]byte(bad)); err == nil {
			t.Fatal("ambiguous status accepted")
		}
	}
}

func TestApprovedArchiveDirectoryRejectsUnexpectedOrChangedInputs(t *testing.T) {
	dir := t.TempDir()
	archives := filepath.Join(dir, "archives")
	if err := os.Mkdir(archives, 0700); err != nil {
		t.Fatal(err)
	}
	data := []byte("authenticated package bytes")
	sum := sha256.Sum256(data)
	packages := []packageIdentity{{Name: "test", Version: "1", Architecture: "arm64", Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}}
	write := func(name string, content []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(archives, name), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("p000.deb", data)
	write("sha256sums", nil)
	if err := verifyApprovedArchives(dir, packages); err != nil {
		t.Fatal(err)
	}
	write("unapproved.deb", data)
	if err := verifyApprovedArchives(dir, packages); err == nil {
		t.Fatal("extra package accepted")
	}
	if err := os.Remove(filepath.Join(archives, "unapproved.deb")); err != nil {
		t.Fatal(err)
	}
	changed := append([]byte{}, data...)
	changed[0] = 'X'
	write("p000.deb", changed)
	if err := verifyApprovedArchives(dir, packages); err == nil {
		t.Fatal("changed archive accepted")
	}
	if err := os.Remove(filepath.Join(archives, "p000.deb")); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(archives, "p000.deb")); err != nil {
		t.Fatal(err)
	}
	if err := verifyApprovedArchives(dir, packages); err == nil {
		t.Fatal("archive symlink accepted")
	}
}

// Optional retained-artifact check is run explicitly during fixture review.
// Ordinary CI still runs every synthetic adversarial regression above.
func TestPinnedOwnedBaselineAndArchiveInventory(t *testing.T) {
	root := os.Getenv("TASK11_OWNED_PREREQ_FIXTURE")
	if root == "" {
		t.Skip("owned authenticated artifact directory not supplied")
	}
	data, err := os.ReadFile(filepath.Join(root, "prerequisites", "guest-dpkg-status"))
	if err != nil {
		t.Fatal(err)
	}
	if err = checkPinned(data, baselineStatusSHA); err != nil {
		t.Fatal(err)
	}
	baseline, err := parsePackageStatus(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline) != 321 {
		t.Fatal("baseline count mismatch")
	}
	lockData, err := os.ReadFile(filepath.Join(root, "prerequisites", "dev-prerequisites.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = checkPinned(lockData, approvedLockSHA); err != nil {
		t.Fatal(err)
	}
	var lock struct {
		Packages []packageIdentity `json:"packages"`
	}
	if err = json.Unmarshal(lockData, &lock); err != nil {
		t.Fatal(err)
	}
	if len(lock.Packages) != 26 {
		t.Fatal("approved count mismatch")
	}
	if err = verifyApprovedArchives(filepath.Join(root, "nested-seed"), lock.Packages); err != nil {
		t.Fatal(err)
	}
	approved := map[string]packageIdentity{}
	for _, p := range lock.Packages {
		approved[p.Name] = p
	}
	if err = verifyPrerequisites(prerequisiteEvidence{Baseline: baseline, Current: baseline, Approved: approved}); err != nil {
		t.Fatal(err)
	}
}

func TestAuthoritativeDPKGJournalCurrentAndFinalViews(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("TASK11_REAL_DPKG_TEST") != "1" {
		t.Skip("explicit owned Linux dpkg-query container required")
	}
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		t.Fatal(err)
	}
	packageText := func(name, version, status, trigger string) string {
		return "Package: " + name + "\nStatus: " + status + "\nArchitecture: arm64\nVersion: " + version + "\nMaintainer: Fixture <fixture@example.invalid>\nDescription: development regression fixture\n" + trigger + "\n"
	}
	baselineText := packageText("libc-bin", "2.41-12+deb13u4", "install ok installed", "") + packageText("man-db", "2.13.1-1", "install ok installed", "")
	baseline, err := parsePackageStatus([]byte(baselineText))
	if err != nil {
		t.Fatal(err)
	}
	library := packageIdentity{Name: "libgcrypt20", Version: "1.11.0-7+deb13u1", Architecture: "arm64"}
	for _, final := range []bool{false, true} {
		t.Run(map[bool]string{false: "current", true: "final"}[final], func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "updates"), 0700); err != nil {
				t.Fatal(err)
			}
			raw := baselineText
			if final {
				raw += packageText(library.Name, library.Version, "install ok installed", "")
			}
			if err := os.WriteFile(filepath.Join(dir, "status"), []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			clean, err := loadCurrentPackageState(dir)
			if err != nil {
				t.Fatal(err)
			}
			e := prerequisiteEvidence{Baseline: baseline, Approved: map[string]packageIdentity{library.Name: library}, Current: clean, Final: final}
			if err = verifyPrerequisites(e); err != nil {
				t.Fatalf("clean setup rejected: %v", err)
			}
			update := packageText("man-db", "2.13.1-1", "install ok triggers-pending", "Triggers-Pending: /usr/share/man\n")
			if err = os.WriteFile(filepath.Join(dir, "updates", "0000"), []byte(update), 0600); err != nil {
				t.Fatal(err)
			}
			actual, err := exec.Command("dpkg-query", "--admindir="+dir, "-W", "-f=${Package}\t${Status}\t${Triggers-Pending}\n", "man-db").CombinedOutput()
			if err != nil {
				t.Fatalf("actual cached dpkg-query: %v: %s", err, actual)
			}
			if !strings.Contains(string(actual), "triggers-pending") || !strings.Contains(string(actual), "/usr/share/man") {
				t.Fatalf("fixture did not create actual pending journal: %s", actual)
			}
			rawAgain, err := os.ReadFile(filepath.Join(dir, "status"))
			if err != nil {
				t.Fatal(err)
			}
			if string(rawAgain) != raw {
				t.Fatal("raw status unexpectedly changed; not reproducing journal divergence")
			}
			e.Current, err = loadCurrentPackageState(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err = verifyPrerequisites(e); err == nil {
				t.Fatalf("%s gate accepted stale raw status while actual dpkg-query reports %s", map[bool]string{false: "current", true: "final"}[final], actual)
			}

			// Query again after removing the pending update: no cached dirty or
			// clean snapshot may be reused across either gate.
			if err = os.Remove(filepath.Join(dir, "updates", "0000")); err != nil {
				t.Fatal(err)
			}
			e.Current, err = loadCurrentPackageState(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err = verifyPrerequisites(e); err != nil {
				t.Fatalf("fresh clean query remained stale: %v", err)
			}
			if err = os.WriteFile(filepath.Join(dir, "updates", "0000"), []byte("malformed journal\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = loadCurrentPackageState(dir); err == nil {
				t.Fatal("malformed effective journal silently fell back to raw status")
			}
		})
	}
}

func TestPackageQueryOutputBound(t *testing.T) {
	out := &packageQueryOutput{limit: 4}
	if n, err := out.Write([]byte("1234")); err != nil || n != 4 {
		t.Fatal(n, err)
	}
	if _, err := out.Write([]byte("5")); err == nil {
		t.Fatal("unbounded output accepted")
	}
	if out.Len() != 4 {
		t.Fatal("overflow was retained")
	}
}

func TestPackageQueryStreamCannotBypassOutputBound(t *testing.T) {
	out := &packageQueryOutput{limit: 4}
	if _, err := io.Copy(out, io.LimitReader(strings.NewReader("12345"), 5)); err == nil {
		t.Fatal("stream fast path bypassed output bound")
	}
	if out.Len() > 4 {
		t.Fatal("stream retained oversized output")
	}
}

// Exercises the real CLI loader against the exact pristine image inventory.
// Requiring historical logs for a clean initial image breaks the positive case;
// treating missing logs as recovery provenance breaks the negative cases.
func TestPristinePrerequisiteCommandWithoutHistory(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("TASK11_PRISTINE_CLI_TEST") != "1" {
		t.Skip("explicit owned Linux container with disposable fixed paths required")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("disposable Docker test container required")
	}
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("/etc/cloud8021x-task11-fixture", []byte("synthetic-only-v1\n"))
	base, err := os.ReadFile("/run/task11-media/base.txt")
	if err != nil {
		t.Fatal(err)
	}
	if err = checkPinned(base, baselineStatusSHA); err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll("/var/lib/dpkg/updates", 0700); err != nil {
		t.Fatal(err)
	}
	packageText := func(name, version, status, trigger string) string {
		return "Package: " + name + "\nStatus: " + status + "\nArchitecture: arm64\nVersion: " + version + "\nMaintainer: Fixture <fixture@example.invalid>\nDescription: disposable CLI regression\n" + trigger + "\n"
	}
	cases := []struct {
		name, extra, journal, history string
		unsafeHistory                 bool
		final, wantOK                 bool
	}{
		{name: "exact clean321 absent history", wantOK: true},
		{name: "pending libc journal absent lineage", journal: packageText("libc-bin", "2.41-12+deb13u4", "install ok triggers-pending", "Triggers-Pending: ldconfig\n")},
		{name: "pending man-db journal", journal: packageText("man-db", "2.13.1-1", "install ok triggers-pending", "Triggers-Pending: /usr/share/man\n")},
		{name: "partial baseline", journal: packageText("libc-bin", "2.41-12+deb13u4", "install ok half-configured", "")},
		{name: "partial approved without lineage", extra: packageText("libgcrypt20", "1.11.0-7+deb13u1", "install ok unpacked", "")},
		{name: "unknown installed extra", extra: packageText("task11-unapproved", "1", "install ok installed", "")},
		{name: "malformed pending journal", journal: "not a dpkg record\n"},
		{name: "final lacks26", final: true},
		{name: "unsafe existing history", history: "existing history\n", unsafeHistory: true},
		{name: "malformed interrupted history", history: "malformed history\n", extra: packageText("libgcrypt20", "1.11.0-7+deb13u1", "install ok unpacked", ""), journal: packageText("libc-bin", "2.41-12+deb13u4", "install ok triggers-pending", "Triggers-Pending: ldconfig\n")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			write("/var/lib/dpkg/status", append(append([]byte(nil), base...), []byte("\n"+tc.extra)...))
			if err := os.Remove("/var/lib/dpkg/updates/0000"); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if tc.journal != "" {
				write("/var/lib/dpkg/updates/0000", []byte(tc.journal))
			}
			if err := os.Remove("/var/log/dpkg.log"); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if _, err := os.Lstat("/var/log/dpkg.log"); !os.IsNotExist(err) {
				t.Fatalf("history must be absent, got %v", err)
			}
			if tc.history != "" {
				write("/var/log/dpkg.log", []byte(tc.history))
				if tc.unsafeHistory {
					if err := os.Chmod("/var/log/dpkg.log", 0666); err != nil {
						t.Fatal(err)
					}
				}
			}
			parsed, err := parsePackageStatus(base)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove("/var/lib/cloud8021x-task11/live-base.tsv"); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if tc.history != "" {
				write("/var/lib/cloud8021x-task11/live-base.tsv", baselineTSV(parsed))
			}
			write("/var/lib/cloud8021x-task11/dpkg-audit", nil)
			cmd := prerequisiteCommand()
			cmd.SilenceErrors, cmd.SilenceUsage = true, true
			cmd.SetArgs([]string{})
			if tc.final {
				cmd.SetArgs([]string{"--final"})
			}
			err = cmd.Execute()
			if tc.wantOK && err != nil {
				t.Fatalf("pristine exact baseline rejected: %v", err)
			}
			if !tc.wantOK && err == nil {
				t.Fatal("dirty/incomplete state accepted without history")
			}
		})
	}
}
