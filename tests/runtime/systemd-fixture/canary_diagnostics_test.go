package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Execute only the real diagnostic prefix, before any platform/package work.
// Replace the fixed console path with an owned failing sink; all external
// journal/poweroff/install commands are synthetic executables on a private PATH.
func canaryDiagnosticRun(t *testing.T, mode string) ([]byte, int, string) {
	t.Helper()
	source, err := os.ReadFile("offline-prereq-canary.sh")
	if err != nil {
		t.Fatal(err)
	}
	prefix, _, found := strings.Cut(string(source), "root=/var/lib/cloud8021x-task11")
	if !found {
		t.Fatal("missing fixed platform boundary")
	}
	prefix = strings.ReplaceAll(prefix, "/dev/hvc0", "${TEST_CONSOLE}")
	dir := t.TempDir()
	for name, script := range map[string]string{
		"dpkg":       "#!/bin/bash\nprintf 'synthetic-dpkg-stderr\\n' >&2\nexit 7\n",
		"journalctl": "#!/bin/bash\nif [[ $1 = --sync ]]; then exit 0; fi\nprintf 'synthetic-journal-record\\n'\n",
		"systemctl":  "#!/bin/bash\nprintf '%s\\n' \"$*\" >> \"$TEST_SHUTDOWN\"\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	shutdown := filepath.Join(dir, "shutdown")
	console := dir // Opening an owned directory for output must fail.
	cmd := exec.Command("/bin/bash", "-c", prefix+"\nif declare -F canary_phase_begin >/dev/null; then canary_phase_begin dpkg-install; fi\ndpkg --install synthetic-only.deb\n")
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
	if strings.Contains(mode, "success") || strings.Contains(mode, "data write failure") || mode == "collector failure" {
		console = filepath.Join(dir, "console")
	}
	if strings.HasPrefix(mode, "delayed") || mode == "data write failure" || mode == "collector failure" {
		// Fail the actual head write inside the timed child, while leaving the
		// child's console open so a later printf would succeed and mask the error.
		script := "#!/bin/bash\n"
		if strings.HasPrefix(mode, "delayed") {
			// A completed journal query must not race its still-running spool reader.
			script += "if [[ $2 = 262001 ]]; then sleep 0.2; fi\n"
		}
		if strings.Contains(mode, "data write failure") {
			script += "if [[ $2 = 262000 ]]; then exec /usr/bin/head \"$@\" 1>&-; fi\n"
		}
		if mode == "collector failure" {
			script += "if [[ $2 = 262001 ]]; then exit 9; fi\n"
		}
		script += "exec /usr/bin/head \"$@\"\n"
		if err := os.WriteFile(filepath.Join(dir, "head"), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "TMPDIR="+dir, "TEST_CONSOLE="+console, "TEST_SHUTDOWN="+shutdown)
	out, runErr := cmd.CombinedOutput()
	if runErr == nil {
		return out, 0, shutdown
	}
	if exit, ok := runErr.(*exec.ExitError); ok {
		return out, exit.ExitCode(), shutdown
	}
	t.Fatal(runErr)
	return nil, 0, ""
}

func TestCanaryJournalErrorAndShutdownSurviveConsoleFailure(t *testing.T) {
	for _, name := range []string{"open failure", "write failure", "data write failure", "success", "delayed data write failure", "delayed success", "collector failure"} {
		t.Run(name, func(t *testing.T) {
			out, code, shutdown := canaryDiagnosticRun(t, name)
			text := string(out)
			if code != 7 || !strings.Contains(text, "synthetic-dpkg-stderr") || !strings.Contains(text, "TASK11_NESTED_PHASE phase=dpkg-install event=begin") || !strings.Contains(text, "TASK11_NESTED_STAGE_EXIT=7 phase=dpkg-install") {
				t.Fatalf("actual error/phase lost to console failure: status=%d %s", code, out)
			}
			if strings.Contains(name, "success") {
				exported, err := os.ReadFile(filepath.Join(filepath.Dir(shutdown), "console"))
				if err != nil || !strings.Contains(string(exported), "synthetic-journal-record") || !strings.Contains(string(exported), "TASK11_JOURNAL_EXPORT query_status=0 truncated=0") || !strings.Contains(text, "TASK11_NESTED_EXPORT_EXIT=0\n") {
					t.Fatalf("valid export failed: %v %s %s", err, exported, out)
				}
			} else if !regexp.MustCompile(`TASK11_NESTED_EXPORT_EXIT=[1-9][0-9]*\n`).Match(out) {
				t.Fatalf("failed console/data export falsely reported success: %s", out)
			}
			if name == "collector failure" && !strings.Contains(text, "collector_status=9") {
				t.Fatalf("actual capture reader exit lost: %s", out)
			}
			called, err := os.ReadFile(shutdown)
			if err != nil || string(called) != "--no-block poweroff\n" {
				t.Fatalf("shutdown skipped or repeated: %v %s", err, called)
			}
		})
	}
}

func TestCanaryJournalExportIsBoundedAndReportsQueryFailure(t *testing.T) {
	source, err := os.ReadFile("offline-prereq-canary.sh")
	if err != nil {
		t.Fatal(err)
	}
	definitions, _, ok := strings.Cut(string(source), "\nset -euo pipefail\ntrap 'canary_exit")
	if !ok {
		t.Fatal("diagnostic definition boundary missing")
	}
	for _, tc := range []struct{ name, command, want string }{
		{"oversize", "head -c 300000 /dev/zero | tr '\\000' x", "truncated=1"},
		{"stderr failure", "printf 'synthetic-query-stderr\\n' >&2; exit 7", "query_status=7"},
		{"timeout", "exec sleep 30", "capture_status=124"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			console := filepath.Join(dir, "console")
			if err := os.WriteFile(filepath.Join(dir, "journalctl"), []byte("#!/bin/bash\n"+tc.command+"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("/bin/bash", "-c", definitions+"\ncanary_export_journal \"$TEST_CONSOLE\"\n")
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "TMPDIR="+dir, "TEST_CONSOLE="+console)
			out, err := cmd.CombinedOutput()
			exported, readErr := os.ReadFile(console)
			if err == nil || readErr != nil || len(exported) > 262144 || !strings.Contains(string(exported), tc.want) {
				t.Fatalf("query failure/cap hidden: err=%v read=%v bytes=%d journal=%s", err, readErr, len(exported), out)
			}
			if tc.name == "stderr failure" && !strings.Contains(string(exported), "synthetic-query-stderr") {
				t.Fatal("query stderr lost")
			}
		})
	}
}

func TestCanaryUnitKeepsDiagnosticStreamsOnBoundedJournal(t *testing.T) {
	source, err := os.ReadFile("cloud-init-nested-user-data.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"StandardOutput=journal", "StandardError=journal", "LogRateLimitIntervalSec=0", "SystemMaxUse=32M", "RuntimeMaxUse=16M", "TimeoutStartSec=440"} {
		if !strings.Contains(string(source), required) {
			t.Fatalf("missing journal/deadline contract %s", required)
		}
	}
}

func TestCanaryBlockedConsoleOpenIsBounded(t *testing.T) {
	source, err := os.ReadFile("offline-prereq-canary.sh")
	if err != nil {
		t.Fatal(err)
	}
	definitions, _, ok := strings.Cut(string(source), "\nset -euo pipefail\ntrap 'canary_exit")
	if !ok {
		t.Fatal("diagnostic definition boundary missing")
	}
	dir := t.TempDir()
	console := filepath.Join(dir, "blocked-console")
	if out, err := exec.Command("mkfifo", console).CombinedOutput(); err != nil {
		t.Fatalf("owned FIFO: %v %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(dir, "journalctl"), []byte("#!/bin/bash\nprintf 'synthetic journal\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	// The outer timeout is a test watchdog only. The inner console-open deadline
	// must return first; otherwise RETURN is absent and the test fails.
	cmd := exec.Command("timeout", "--kill-after=1s", "12s", "/bin/bash", "-c", definitions+"\ncanary_export_journal \"$TEST_CONSOLE\"; printf 'RETURN=%s\\n' \"$?\"\n")
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "TMPDIR="+dir, "TEST_CONSOLE="+console)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "RETURN=124") {
		t.Fatalf("console open bypassed inner deadline: %v %s", err, out)
	}
}

func TestCanaryCaptureJoinIsBounded(t *testing.T) {
	source, err := os.ReadFile("offline-prereq-canary.sh")
	if err != nil {
		t.Fatal(err)
	}
	definitions, _, ok := strings.Cut(string(source), "\nset -euo pipefail\ntrap 'canary_exit")
	if !ok {
		t.Fatal("diagnostic definition boundary missing")
	}
	dir := t.TempDir()
	for name, script := range map[string]string{
		"journalctl": "#!/bin/bash\nprintf 'synthetic journal\\n'\n",
		"head":       "#!/bin/bash\nif [[ $2 = 262001 ]]; then exec sleep 30; fi\nexec /usr/bin/head \"$@\"\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	console := filepath.Join(dir, "console")
	cmd := exec.Command("timeout", "--kill-after=1s", "12s", "/bin/bash", "-c", definitions+"\ncanary_export_journal \"$TEST_CONSOLE\"; printf 'RETURN=%s\\n' \"$?\"\n")
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "TMPDIR="+dir, "TEST_CONSOLE="+console)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "capture_status=124") || !strings.Contains(string(out), "RETURN=1") {
		t.Fatalf("capture reader escaped whole-pipeline deadline: %v %s", err, out)
	}
}
