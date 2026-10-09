package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Never include child output in errors: a captured authorization envelope
// contains a private webhook key. Callers journal only digest and byte count.
type boundedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.buffer.Len() {
		return 0, errors.New("child output bound exceeded")
	}
	return b.buffer.Write(p)
}
func runBounded(ctx context.Context, argv []string, input []byte, limit int, timeout time.Duration) ([]byte, error) {
	return runBoundedFiles(ctx, argv, input, limit, timeout, nil)
}
func runBoundedFiles(ctx context.Context, argv []string, input []byte, limit int, timeout time.Duration, files []*os.File) ([]byte, error) {
	return runBoundedConfigured(ctx, argv, input, limit, timeout, files, nil)
}
func runBoundedConfigured(ctx context.Context, argv []string, input []byte, limit int, timeout time.Duration, files []*os.File, configure func(*exec.Cmd)) ([]byte, error) {
	if len(argv) == 0 || limit < 1 || limit > 40<<20 || timeout <= 0 || timeout > 20*time.Minute {
		return nil, errors.New("invalid bounded invocation")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	// Leaf/inner calls use a separate group. Namespace operations MUST wrap
	// this primitive with runNamespaceBounded; group-only cancellation cannot
	// prove nested descendants gone. Prior side effects require reconciliation.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return unix.Kill(-cmd.Process.Pid, unix.SIGKILL) }
	if configure != nil {
		configure(cmd)
	}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "HOME=/root"}
	cmd.Stdin = bytes.NewReader(input)
	cmd.ExtraFiles = files
	out := &boundedBuffer{limit: limit}
	stderr := &boundedBuffer{limit: 64 << 10}
	cmd.Stdout = out
	cmd.Stderr = stderr
	cmd.WaitDelay = 3 * time.Second
	if err := cmd.Run(); err != nil {
		return nil, errors.New("bounded child failed (private output withheld)")
	}
	return out.buffer.Bytes(), nil
}
func boundedInput(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if int64(len(b)) > limit {
		return nil, errors.New("input exceeds bound")
	}
	return b, err
}
