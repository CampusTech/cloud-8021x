package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const canaryBeforeBoot = "dc8c2e8a-01f7-481a-86f9-e20bd612b1b1"
const canaryAfterBoot = "458e688d-219f-4938-bbbf-2e238b2d8557"

func canaryRebootRun(t *testing.T, mode string) (string, int, string) {
	t.Helper()
	source, err := os.ReadFile("offline-prereq-canary.sh")
	if err != nil {
		t.Fatal(err)
	}
	prefix, _, ok := strings.Cut(string(source), "root=/var/lib/cloud8021x-task11")
	if !ok {
		t.Fatal("platform boundary absent")
	}
	_, observer, ok := strings.Cut(string(source), "canary_phase_begin nested-reboot\n")
	if !ok {
		t.Fatal("reboot observer absent")
	}
	observer, _, ok = strings.Cut(observer, "nsenter -t \"$leader\" -m -p -u -n -C -r -w /bin/sh -s <<'NODE'")
	if !ok {
		t.Fatal("post-reboot proof boundary absent")
	}
	dir := t.TempDir()
	scripts := map[string]string{
		"machinectl": `printf '%s\n' "$*" >> "$TEST_DIR/machinectl.calls"
if [[ $1 = reboot ]]; then
 if [[ $TEST_MODE = reboot-error ]]; then exit 7; fi
 exit 0
fi
if [[ $TEST_MODE = absent ]]; then exit 0; fi
if [[ $TEST_MODE = terminated133 ]]; then printf 'synthetic-no-machine\n' >&2; exit 1; fi
if [[ $TEST_MODE = leader-error ]]; then printf 'synthetic-leader-error\n' >&2; exit 5; fi
printf '44\n'
`,
		"nsenter": `printf '%s\n' "$*" >> "$TEST_DIR/nsenter.calls"
if [[ $TEST_MODE = read-error ]]; then printf 'synthetic-read-error\n' >&2; exit 6; fi
if [[ $TEST_MODE = changed ]]; then printf '%s\n' "$TEST_AFTER"; else printf '%s\n' "$TEST_BEFORE"; fi
`,
		"sleep": `[[ $1 = .2 ]] || exit 90
printf '%s\n' "$1" >> "$TEST_DIR/sleep.calls"
`,
		"journalctl": `[[ $1 = --sync ]] && exit 0
printf '%s\n' "$*" >> "$TEST_DIR/journal.calls"
if [[ $* = *task11-nested.service* ]]; then printf 'synthetic-nested-journal\n'; else printf 'synthetic-main-journal\n'; fi
`,
		"systemctl": `if [[ $1 = show ]]; then
 printf '%s\n' "$*" >> "$TEST_DIR/unit.calls"
 if [[ $TEST_MODE = terminated133 ]]; then
  printf 'ActiveState=inactive\nSubState=dead\nResult=success\nExecMainStatus=133\nMainPID=0\n'
 else printf 'ActiveState=failed\nSubState=failed\nResult=exit-code\nExecMainStatus=1\nMainPID=0\n'; fi
else printf '%s\n' "$*" >> "$TEST_DIR/shutdown.calls"; fi
`,
	}
	for name, script := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/bash\n"+script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	prefix = strings.ReplaceAll(prefix, "/dev/hvc0", "${TEST_CONSOLE}")
	cmd := exec.Command("/bin/bash", "-c", prefix+"\nbefore=$TEST_BEFORE\nleader=44\ncanary_phase_begin nested-reboot\n"+observer+"\ncanary_phase_begin complete\n")
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "TMPDIR="+dir, "TEST_DIR="+dir, "TEST_MODE="+mode, "TEST_CONSOLE="+filepath.Join(dir, "console"), "TEST_BEFORE="+canaryBeforeBoot, "TEST_AFTER="+canaryAfterBoot)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0, dir
	}
	if exit, ok := err.(*exec.ExitError); ok {
		return string(out), exit.ExitCode(), dir
	}
	t.Fatal(err)
	return "", 0, ""
}

func TestCanaryRebootRefusalIdentifiesObservedFailure(t *testing.T) {
	for _, tc := range []struct {
		mode, statuses string
		exit, polls    int
	}{
		{"stable", "reboot_exit=0 leader_exit=0 boot_read_exit=0", 1, 150},
		{"absent", "reboot_exit=0 leader_exit=0 boot_read_exit=not-attempted", 1, 150},
		{"leader-error", "reboot_exit=0 leader_exit=5 boot_read_exit=not-attempted", 1, 150},
		{"terminated133", "reboot_exit=0 leader_exit=1 boot_read_exit=not-attempted", 1, 150},
		{"read-error", "reboot_exit=0 leader_exit=0 boot_read_exit=6", 1, 150},
		{"reboot-error", "reboot_exit=7 leader_exit=not-attempted boot_read_exit=not-attempted", 7, 0},
		{"changed", "", 0, 1},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			out, code, dir := canaryRebootRun(t, tc.mode)
			if code != tc.exit {
				t.Fatalf("original observer exit changed: got%d want%d: %s", code, tc.exit, out)
			}
			calls, err := os.ReadFile(filepath.Join(dir, "machinectl.calls"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(calls), "show task11-nested-canary --property=Leader --value\n") != tc.polls {
				t.Fatalf("poll count changed: %s", calls)
			}
			sleeps, sleepErr := os.ReadFile(filepath.Join(dir, "sleep.calls"))
			wantSleeps := tc.polls
			if tc.mode == "changed" {
				wantSleeps = 0
			}
			if (sleepErr != nil && !os.IsNotExist(sleepErr)) || strings.Count(string(sleeps), ".2\n") != wantSleeps {
				t.Fatalf("poll sleep count/argument changed: %v %s", sleepErr, sleeps)
			}
			if strings.Count(string(calls), "reboot task11-nested-canary\n") != 1 {
				t.Fatalf("reboot retried: %s", calls)
			}
			shutdown, err := os.ReadFile(filepath.Join(dir, "shutdown.calls"))
			if err != nil || string(shutdown) != "--no-block poweroff\n" {
				t.Fatalf("shutdown not exactly once: %v %s", err, shutdown)
			}
			if tc.mode == "changed" {
				if !strings.Contains(out, "TASK11_NODE_AFTER="+canaryAfterBoot) || strings.Contains(out, "TASK11_REBOOT_TERMINAL") {
					t.Fatalf("positive reboot observer altered: %s", out)
				}
				return
			}
			unitFields := []string{"ActiveState=failed", "SubState=failed", "Result=exit-code", "ExecMainStatus=1"}
			if tc.mode == "terminated133" {
				unitFields = []string{"ActiveState=inactive", "SubState=dead", "Result=success", "ExecMainStatus=133"}
			}
			wants := append([]string{"TASK11_REBOOT_TERMINAL", tc.statuses, "before=" + canaryBeforeBoot, "MainPID=0", "synthetic-nested-journal"}, unitFields...)
			for _, want := range wants {
				if !strings.Contains(out, want) {
					t.Fatalf("actual refusal missing bounded terminal diagnostic %q: %s", want, out)
				}
			}
			journal, err := os.ReadFile(filepath.Join(dir, "journal.calls"))
			if err != nil {
				t.Fatal(err)
			}
			nested := strings.Index(string(journal), "task11-nested.service")
			main := strings.Index(string(journal), "task11-nested-prep.service")
			if nested < 0 || main <= nested {
				t.Fatalf("nested diagnostic not before main snapshot: %s", journal)
			}
		})
	}
}

func TestCanaryLateStatusesReachSerialAfterSnapshot(t *testing.T) {
	_, code, shutdown := canaryDiagnosticRun(t, "success")
	console, err := os.ReadFile(filepath.Join(filepath.Dir(shutdown), "console"))
	if err != nil || code != 7 {
		t.Fatalf("synthetic original status: %v code%d", err, code)
	}
	text := string(console)
	snapshot := strings.Index(text, "TASK11_JOURNAL_EXPORT")
	for _, frame := range []string{"T11_EXPORT=0\n", "T11_SHUTDOWN=0\n"} {
		if strings.Index(text, frame) <= snapshot {
			t.Fatalf("late status missing after actual serial snapshot: %q %s", frame, text)
		}
	}
}

func canaryDiagnosticDefinitions(t *testing.T) string {
	t.Helper()
	source, err := os.ReadFile("offline-prereq-canary.sh")
	if err != nil {
		t.Fatal(err)
	}
	definitions, _, ok := strings.Cut(string(source), "\nset -euo pipefail\ntrap 'canary_exit")
	if !ok {
		t.Fatal("diagnostic definition boundary absent")
	}
	return definitions
}

func TestCanaryRebootDiagnosticOutputIsBoundedAndEscaped(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"machinectl", "systemctl", "journalctl"} {
		script := "#!/bin/bash\n/usr/bin/head -c 70000 /dev/zero | tr '\\000' x\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	hostile := "$(touch " + filepath.Join(dir, "injected") + ")\nTASK11_REBOOT_TERMINAL forged\n" + strings.Repeat("x", 100000)
	cmd := exec.Command("timeout", "--kill-after=1s", "12s", "/bin/bash", "-c", canaryDiagnosticDefinitions(t)+"\nbefore=$TEST_VALUE; after=$TEST_VALUE; leader=$TEST_VALUE; canary_reboot_diagnostics\n")
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "TEST_VALUE="+hostile)
	out, err := cmd.CombinedOutput()
	if err != nil || len(out) > 65536 {
		t.Fatalf("diagnostic timeout/output bound: %v bytes%d %s", err, len(out), out)
	}
	if strings.Contains(string(out), "\nTASK11_REBOOT_TERMINAL forged") || !strings.Contains(string(out), `\nTASK11_REBOOT_TERMINAL forged\n`) {
		t.Fatalf("public metadata was not escaped: %s", out[:min(1500, len(out))])
	}
	if _, err := os.Stat(filepath.Join(dir, "injected")); !os.IsNotExist(err) {
		t.Fatalf("metadata executed or unexpected stat: %v", err)
	}
	for _, want := range []string{"before_bytes=", "after_bytes=", "leader_bytes=", "limit_bytes=4096", "limit_bytes=32768 completeness=not_asserted"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("missing bounded output annotation %q", want)
		}
	}
}

func TestCanaryRebootDiagnosticHangRetainsOriginalExitAndShutdown(t *testing.T) {
	definitions := canaryDiagnosticDefinitions(t)
	dir := t.TempDir()
	for name, body := range map[string]string{
		"machinectl": "exec /bin/sleep 30\n",
		"journalctl": "exit 0\n",
		"systemctl":  "printf '%s\\n' \"$*\" >> \"$TEST_SHUTDOWN\"\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/bash\n"+body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	script := definitions + "\ncanary_export_journal() { return 0; }\ntrap 'canary_exit $?' EXIT\ncanary_phase=nested-reboot\nexit 7\n"
	script = strings.ReplaceAll(script, "/dev/hvc0", "${TEST_CONSOLE}")
	cmd := exec.Command("timeout", "--kill-after=1s", "12s", "/bin/bash", "-c", script)
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "TEST_CONSOLE="+filepath.Join(dir, "console"), "TEST_SHUTDOWN="+filepath.Join(dir, "shutdown"))
	out, err := cmd.CombinedOutput()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 7 || !strings.Contains(string(out), "TASK11_REBOOT_DIAGNOSTICS_EXIT=124") {
		t.Fatalf("diagnostic deadline replaced original exit: %v %s", err, out)
	}
	shutdown, err := os.ReadFile(filepath.Join(dir, "shutdown"))
	if err != nil || string(shutdown) != "--no-block poweroff\n" {
		t.Fatalf("shutdown skipped/repeated: %v %s", err, shutdown)
	}
}

func TestCanaryBothLateSerialChildrenFailOrHangIndependently(t *testing.T) {
	for _, mode := range []string{"open failure", "write failure", "blocked open", "shutdown failure"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			console := filepath.Join(dir, "console")
			for name, body := range map[string]string{
				"journalctl": "exit 0\n",
				"systemctl":  "printf '%s\\n' \"$*\" >> \"$TEST_SHUTDOWN\"\nif [[ $TEST_MODE = 'shutdown failure' ]]; then exit 5; fi\n",
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/bash\n"+body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			script := canaryDiagnosticDefinitions(t) + "\ncanary_export_journal() { return 0; }\ntrap 'canary_exit $?' EXIT\ncanary_phase=synthetic\nexit 7\n"
			script = strings.ReplaceAll(script, "/dev/hvc0", "${TEST_CONSOLE}")
			cmd := exec.Command("timeout", "--kill-after=1s", "8s", "/bin/bash", "-c", script)
			if mode == "open failure" {
				console = dir
			}
			if mode == "blocked open" {
				if out, err := exec.Command("mkfifo", console).CombinedOutput(); err != nil {
					t.Fatalf("owned FIFO: %v %s", err, out)
				}
			}
			if mode == "write failure" {
				read, write, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				if err := read.Close(); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := write.Close(); err != nil {
						t.Error(err)
					}
				}()
				cmd.ExtraFiles = []*os.File{write}
				console = "/dev/fd/3"
			}
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "TEST_CONSOLE="+console, "TEST_SHUTDOWN="+filepath.Join(dir, "shutdown"), "TEST_MODE="+mode)
			out, err := cmd.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 7 {
				t.Fatalf("serial child masked original7: %v %s", err, out)
			}
			for _, kind := range []string{"EXPORT", "SHUTDOWN"} {
				pattern := `TASK11_STATUS_SERIAL_EXIT kind=` + kind + ` status=([1-9][0-9]*)\n`
				if mode == "blocked open" {
					pattern = `TASK11_STATUS_SERIAL_EXIT kind=` + kind + ` status=124\n`
				}
				if mode == "shutdown failure" {
					pattern = `TASK11_STATUS_SERIAL_EXIT kind=` + kind + ` status=0\n`
				}
				if !regexp.MustCompile(pattern).Match(out) {
					t.Fatalf("serial child failure/timeout not preserved: %s", out)
				}
			}
			shutdown, err := os.ReadFile(filepath.Join(dir, "shutdown"))
			if err != nil || string(shutdown) != "--no-block poweroff\n" {
				t.Fatalf("shutdown skipped/repeated: %v %s", err, shutdown)
			}
			if mode == "shutdown failure" {
				data, err := os.ReadFile(console)
				if err != nil || string(data) != "T11_EXPORT=0\nT11_SHUTDOWN=5\n" {
					t.Fatalf("tiny serial status values lost: %v %s", err, data)
				}
			}
		})
	}
}

func TestCanaryLateFramesRetainTotalSerialCap(t *testing.T) {
	dir := t.TempDir()
	console := filepath.Join(dir, "console")
	script := "#!/bin/bash\n/usr/bin/head -c 262001 /dev/zero | tr '\\000' x\nexec /bin/sleep 30\n"
	if err := os.WriteFile(filepath.Join(dir, "journalctl"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("timeout", "--kill-after=1s", "12s", "/bin/bash", "-c", canaryDiagnosticDefinitions(t)+"\ncanary_export_journal \"$TEST_CONSOLE\"\ncanary_serial_status \"$TEST_CONSOLE\" EXPORT 255\ncanary_serial_status \"$TEST_CONSOLE\" SHUTDOWN 255\n")
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "TMPDIR="+dir, "TEST_CONSOLE="+console)
	out, err := cmd.CombinedOutput()
	data, readErr := os.ReadFile(console)
	if err != nil || readErr != nil || !strings.Contains(string(out), "capture_status=124") {
		t.Fatalf("saturated timeout setup: %v %v %s", err, readErr, out)
	}
	if len(data) > 262144 {
		t.Fatalf("post-snapshot frames exceed256KiB: %d bytes", len(data))
	}
}

func TestCanaryRebootDiagnosticProbeFailuresRemainExplicit(t *testing.T) {
	dir := t.TempDir()
	for name, code := range map[string]int{"machinectl": 5, "systemctl": 6, "journalctl": 7} {
		script := fmt.Sprintf("#!/bin/bash\nprintf 'synthetic-%s-stderr\\n' >&2\nexit %d\n", name, code)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("/bin/bash", "-c", canaryDiagnosticDefinitions(t)+"\ncanary_reboot_diagnostics\n")
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("diagnostic reporter itself failed: %v %s", err, out)
	}
	for _, want := range []string{"TASK11_REBOOT_MACHINE_STATUS exit=5 collector=0", "TASK11_REBOOT_UNIT_STATUS exit=6 collector=0", "TASK11_REBOOT_JOURNAL_STATUS exit=7 collector=0", "synthetic-machinectl-stderr", "synthetic-systemctl-stderr", "synthetic-journalctl-stderr"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("lost actual probe error %q: %s", want, out)
		}
	}
}

func TestCanarySerialStatusRejectsUntrustedFrames(t *testing.T) {
	dir := t.TempDir()
	console := filepath.Join(dir, "console")
	for _, tc := range []struct{ kind, status string }{{"OTHER", "0"}, {"EXPORT", "256"}, {"SHUTDOWN", "-1"}, {"EXPORT", "0\nforged"}, {"EXPORT", strings.Repeat("1", 2000)}} {
		cmd := exec.Command("/bin/bash", "-c", canaryDiagnosticDefinitions(t)+"\ncanary_serial_status \"$TEST_CONSOLE\" \"$TEST_KIND\" \"$TEST_STATUS\"\n")
		cmd.Env = append(os.Environ(), "TEST_CONSOLE="+console, "TEST_KIND="+tc.kind, "TEST_STATUS="+tc.status)
		out, err := cmd.CombinedOutput()
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 2 || len(out) != 0 {
			t.Fatalf("untrusted frame admitted: %v %s", err, out)
		}
	}
	if _, err := os.Stat(console); !os.IsNotExist(err) {
		t.Fatalf("invalid frame touched serial sink: %v", err)
	}
}

func TestCanaryKeepUnitDelegatesOnlyRequestedReboot(t *testing.T) {
	source, err := os.ReadFile("offline-prereq-canary.sh")
	if err != nil {
		t.Fatal(err)
	}
	_, command, ok := strings.Cut(string(source), "\nsystemd-run --unit=task11-nested ")
	if !ok {
		t.Fatal("fixed transient unit invocation absent")
	}
	command, _, ok = strings.Cut(command, "\nleader=''\n")
	if !ok {
		t.Fatal("transient invocation boundary absent")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "systemd-run"), []byte("#!/bin/bash\nprintf '%s\\000' \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/bash", "-c", "root=$TEST_ROOT\nsystemd-run --unit=task11-nested "+command)
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "TEST_ROOT="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("synthetic transient argument capture: %v %s", err, out)
	}
	args := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
	counts := map[string]int{}
	for _, arg := range args {
		counts[arg]++
	}
	for _, required := range []string{"--unit=task11-nested", "--property=RestartForceExitStatus=133", "--property=SuccessExitStatus=133", "--property=Delegate=yes", "--property=KillMode=mixed", "--property=DevicePolicy=closed", "--property=DeviceAllow=/dev/loop-control rw", "--property=DeviceAllow=block-loop rwm", "/usr/bin/systemd-nspawn", "--boot", "--keep-unit", "--machine=task11-nested-canary", "--network-bridge=c8021x11", "--private-users=no", "--console=pipe"} {
		if counts[required] != 1 {
			t.Errorf("actual transient argv missing/duplicated exact managed-reboot contract %q: %q", required, args)
		}
	}
	for _, arg := range args {
		if strings.HasPrefix(arg, "--property=Restart=") || strings.HasPrefix(arg, "--property=RestartForceExitStatus=") && arg != "--property=RestartForceExitStatus=133" || strings.HasPrefix(arg, "--property=SuccessExitStatus=") && arg != "--property=SuccessExitStatus=133" {
			t.Fatalf("general retry/status broadening: %s", arg)
		}
	}
}
