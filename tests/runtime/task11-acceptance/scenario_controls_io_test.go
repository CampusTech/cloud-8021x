package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
)

func TestScenarioControlsRetainProtectedMeasurement(t *testing.T) {
	root := recordFixture(t)
	path := filepath.Join(root, "unit.service")
	raw := []byte("[Service]\nExecStart=/fixed/shipping/program\n")
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	got, err := controlProtectedFile(path, os.Geteuid(), 0644, 4096)
	if err != nil || string(got) != string(raw) {
		t.Fatalf("protected measurement refused: %v", err)
	}
	if _, err := controlProtectedFile(path, os.Geteuid(), 0600, 4096); err == nil {
		t.Fatal("private600 expectation accepted installed644")
	}
	if _, err := controlProtectedFile(path, os.Geteuid(), 0644, 4); err == nil {
		t.Fatal("oversized measurement accepted")
	}
	if err := os.Link(path, path+"-hard"); err != nil {
		t.Fatal(err)
	}
	if _, err := controlProtectedFile(path, os.Geteuid(), 0644, 4096); err == nil {
		t.Fatal("multiple links accepted")
	}
	if err := os.Remove(path + "-hard"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, path+"-link"); err != nil {
		t.Fatal(err)
	}
	if _, err := controlProtectedFile(path+"-link", os.Geteuid(), 0644, 4096); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.Chmod(path, 0664); err != nil {
		t.Fatal(err)
	}
	if _, err := controlProtectedFile(path, os.Geteuid(), 0644, 4096); err == nil {
		t.Fatal("writable unit accepted")
	}
}
func TestScenarioControlsFixedFragmentSpelling(t *testing.T) {
	for _, name := range []string{"/usr/lib/systemd/system/freeradius.service", "/lib/systemd/system/freeradius.service"} {
		if got := controlFragmentPath(name); got != "/usr/lib/systemd/system/freeradius.service" {
			t.Fatalf("actual Debian spelling redirected: %s", got)
		}
	}
}
func TestScenarioControlsClosedCleanupFrame(t *testing.T) {
	if pid, err := parseControlPIDLine([]byte("123\n")); err != nil || pid != 123 {
		t.Fatal(pid, err)
	}
	for _, raw := range []string{"1\n", "0123\n", "123", "123\n456\n", "123 \n", strings.Repeat("1", 40) + "\n"} {
		if _, err := parseControlPIDLine([]byte(raw)); err == nil {
			t.Fatal("ambiguous process frame accepted")
		}
	}
	for _, role := range []string{"worker", "leaf", "sentinel"} {
		if !controlCleanupRole(role) {
			t.Fatal(role)
		}
	}
	for _, role := range []string{"", "Worker", "bash", "leaf --path=/tmp"} {
		if controlCleanupRole(role) {
			t.Fatal("arbitrary cleanup program accepted")
		}
	}
}

func TestScenarioControlsExecutableHashStreamsBoundedBytes(t *testing.T) {
	root := recordFixture(t)
	path := filepath.Join(root, "measured-executable")
	raw := []byte(strings.Repeat("publicELF", 10000))
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if got, err := controlStreamDigest(f, int64(len(raw))); err != nil || got != adoption.Digest(raw) {
		t.Fatal("actual exact executable bytes refused", err)
	}
	if _, err = f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := controlStreamDigest(f, int64(len(raw)-1)); err == nil {
		t.Fatal("oversized executable accepted")
	}
}

func TestScenarioControlsClosedHelperLeafMappingFrame(t *testing.T) {
	for _, test := range []struct {
		raw          string
		helper, leaf int
	}{
		{"23 24\n", 23, 24},
		{"23 23\n", 23, 23},
	} {
		frame, err := parseControlProbeLine([]byte(test.raw))
		if err != nil || frame.helper != test.helper || frame.leaf != test.leaf {
			t.Fatal("actual local helper/leaf frame refused", frame, err)
		}
	}
	for _, raw := range []string{"23\n", "23 24", "23  24\n", "23\t24\n", "023 24\n", "23 024\n", "1 24\n", "23 1\n", "23 24 25\n", "23 24\n25 26\n", strings.Repeat("1", 65) + "\n"} {
		if _, err := parseControlProbeLine([]byte(raw)); err == nil {
			t.Fatal("ambiguous helper/leaf frame accepted")
		}
	}
}

func TestScenarioControlsOuterStatusMappingMustBindBothLevels(t *testing.T) {
	for _, raw := range []string{
		"NSpid:\t300\t23\n",
		"Pid:\t300\n",
		"Pid:\t301\nNSpid:\t300\t23\n",
		"Pid:\t0300\nNSpid:\t300\t23\n",
		"Pid:\t300\nPid:\t300\nNSpid:\t300\t23\n",
		"Pid:\t300\nNSpid:\t300\t23\t7\n",
	} {
		if _, _, err := controlPIDMapping([]byte(raw)); err == nil {
			t.Fatal("unbound outer/local status mapping accepted")
		}
	}
}
