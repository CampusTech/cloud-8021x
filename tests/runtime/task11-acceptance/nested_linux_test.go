//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Opt-in negative reproducer for the original group-only runner. It MUST fail
// until run by the later real delegated-cgroup/namespace acceptance fixture.
// An ordinary root suite must not launch process-tree fixtures implicitly.
func TestNestedSeparateGroupsOriginalCancellation(t *testing.T) {
	if os.Getenv("TASK11_NESTED_RED") != "1" {
		t.Skip("explicit bounded Linux reproducer only; real cgroup/PID-namespace GREEN remains a guest gate")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	sentinel := exec.Command(exe, "-test.run=^TestNestedOperationHelper$", "--", "sentinel", dir)
	if err = sentinel.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sentinel.Process.Kill(); _ = sentinel.Wait() }()
	_, err = runBounded(context.Background(), []string{exe, "-test.run=^TestNestedOperationHelper$", "--", "middle", dir}, nil, 4096, 2*time.Second)
	if err == nil {
		t.Fatal("outer deadline did not expire")
	}
	var pids []int
	for _, name := range []string{"worker", "leaf"} {
		b, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			t.Fatal(e)
		}
		pid, e := strconv.Atoi(string(b))
		if e != nil || pid < 2 {
			t.Fatal("invalid owned PID")
		}
		pids = append(pids, pid)
	}
	defer func() {
		for _, pid := range pids {
			_ = unix.Kill(pid, unix.SIGKILL)
		}
		for range 100 {
			var status unix.WaitStatus
			_, _ = unix.Wait4(-1, &status, unix.WNOHANG, nil)
			time.Sleep(time.Millisecond)
		}
	}()
	if err = unix.Kill(sentinel.Process.Pid, 0); err != nil {
		t.Fatal("unrelated sentinel was killed")
	}
	for _, pid := range pids {
		if unix.Kill(pid, 0) == nil {
			t.Errorf("outer timeout left owned separate-process-group descendant alive: pid=%d", pid)
		}
	}
}
func TestNestedOperationHelper(t *testing.T) {
	index := -1
	for i, a := range os.Args {
		if a == "--" {
			index = i
			break
		}
	}
	if index < 0 {
		return
	}
	args := os.Args[index+1:]
	if len(args) != 2 {
		os.Exit(3)
	}
	mode, dir := args[0], args[1]
	switch mode {
	case "middle":
		exe, err := os.Executable()
		if err != nil {
			os.Exit(4)
		}
		_, err = runBounded(context.Background(), []string{exe, "-test.run=^TestNestedOperationHelper$", "--", "worker", dir}, nil, 4096, 20*time.Second)
		if err != nil {
			os.Exit(5)
		}
	case "worker":
		exe, err := os.Executable()
		if err != nil {
			os.Exit(6)
		}
		child := exec.Command(exe, "-test.run=^TestNestedOperationHelper$", "--", "leaf", dir)
		child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err = child.Start(); err != nil {
			os.Exit(7)
		}
		if err = os.WriteFile(filepath.Join(dir, "worker"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			os.Exit(8)
		}
		if err = child.Wait(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			os.Exit(9)
		}
	case "leaf", "sentinel":
		if err := os.WriteFile(filepath.Join(dir, mode), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			os.Exit(10)
		}
		time.Sleep(30 * time.Second)
	default:
		os.Exit(11)
	}
}
