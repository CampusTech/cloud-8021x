package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Evaluate actual argument/deadline code without loading Virtualization or
// starting a VM. Arbitrary durations remain forbidden.
func TestOwnedVMRunnerBoundedInstalledWatchdog(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS Swift runner")
	}
	raw, err := os.ReadFile("zero-nic-vm.swift")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	start := strings.Index(source, "let args = CommandLine.arguments\n")
	end := strings.Index(source, "\nlet delegate = StopDelegate()")
	deadline := strings.Index(source, "    let watchdogSeconds: Double =")
	if start < 0 || end <= start || deadline < end {
		t.Fatal("actual runner blocks unavailable")
	}
	line := strings.SplitN(source[deadline:], "\n", 2)[0]
	program := "import Foundation\n" + source[start:end] + "\n" + strings.TrimSpace(line) + "\nprint(Int(watchdogSeconds))\n"
	dir := t.TempDir()
	input, binary := filepath.Join(dir, "watchdog.swift"), filepath.Join(dir, "watchdog")
	if err := os.WriteFile(input, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	build := exec.CommandContext(ctx, "/usr/bin/swiftc", "-module-cache-path", filepath.Join(dir, "swift-cache"), input, "-o", binary)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("compile actual guard: %v: %s", err, output)
	}
	for _, tc := range []struct {
		name, argument, want string
		accepted             bool
	}{
		{"default", "", "240", true}, {"preparation", "600", "600", true}, {"installed", "3600", "3600", true},
		{"zero", "0", "", false}, {"negative", "-1", "", false}, {"arbitrary", "601", "", false},
		{"above-bound", "3601", "", false}, {"unbounded", "999999999", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"owned-disk", "owned-readonly-media", "owned-efi"}
			if tc.argument != "" {
				args = append(args, tc.argument)
			}
			output, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
			if tc.accepted {
				if err != nil || strings.TrimSpace(string(output)) != tc.want {
					t.Fatalf("actual argument %q: output=%q error=%v; want %s", tc.argument, output, err, tc.want)
				}
			} else if err == nil {
				t.Fatalf("unapproved deadline %q accepted: %q", tc.argument, output)
			}
		})
	}
}
