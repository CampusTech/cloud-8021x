package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"time"

	"golang.org/x/sys/unix"
)

type boundedOutput struct {
	bytes.Buffer
	limit int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, errors.New("operation output exceeds bound")
	}
	return b.Buffer.Write(p)
}

type runner struct{ p plan }

func (r runner) call(ctx context.Context, name string, args ...string) ([]byte, error) {
	p, ok := r.p.Tools[name]
	if !ok {
		p, ok = r.p.Helpers[name]
	}
	if !ok {
		return nil, errors.New("unknown fixed operation tool")
	}
	return executePinned(ctx, p, args, nil)
}
func executePinned(ctx context.Context, p pin, args []string, input []byte) ([]byte, error) {
	return executeWithFiles(ctx, p, args, input, nil)
}
func executeWithFiles(ctx context.Context, p pin, args []string, input []byte, files []*os.File) ([]byte, error) {
	f, e := openPinned(p.Path, p.SHA256, 160<<20, false)
	if e != nil {
		return nil, e
	}
	defer func() { _ = f.Close() }()
	st, e := f.Stat()
	if e != nil || st.Mode().Perm()&0111 == 0 {
		return nil, errors.New("fixed tool is not executable")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", args...)
	cmd.ExtraFiles = append([]*os.File{f}, files...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive"}
	cmd.Stdin = bytes.NewReader(input)
	cmd.SysProcAttr = &unix.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
	}
	cmd.WaitDelay = 2 * time.Second
	out := &boundedOutput{limit: 4 << 20}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	if e = cmd.Run(); e != nil {
		return nil, errors.New("fixed platform operation failed; partial effects require inspection")
	}
	return out.Bytes(), nil
}
