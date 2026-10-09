package main

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

const outputLimit = 32 << 10

func TestBoundedCopyThroughActualPipe(t *testing.T) {
	for _, size := range []int{outputLimit, outputLimit + 1, outputLimit * 3} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			read, write, e := os.Pipe()
			if e != nil {
				t.Fatal(e)
			}
			defer func() { _ = read.Close(); _ = write.Close() }()
			done := make(chan error, 1)
			go func() {
				_, e := io.Copy(write, strings.NewReader(strings.Repeat("x", size)))
				_ = write.Close()
				done <- e
			}()
			b := &boundedBuffer{limit: outputLimit}
			_, e = io.Copy(b, read)
			_ = read.Close()
			<-done
			if size == outputLimit {
				if e != nil || b.Len() != size {
					t.Fatal("exact boundary refused", b.Len(), e)
				}
			} else if e == nil || b.Len() > outputLimit {
				t.Fatalf("pipe copy bypassed output bound: retained=%d error=%v", b.Len(), e)
			}
		})
	}
}
func TestBoundedActualSubprocessStdoutAndStderr(t *testing.T) {
	for _, size := range []int{outputLimit, outputLimit + 1, outputLimit * 3} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			exe, e := os.Executable()
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestBoundedOutputChild$")
			cmd.Env = append(os.Environ(), "TASK11_AUDIT_OUTPUT_BYTES="+strconv.Itoa(size))
			b := &boundedBuffer{limit: outputLimit}
			cmd.Stdout = b
			cmd.Stderr = b
			e = cmd.Run()
			if ctx.Err() != nil {
				t.Fatal("subprocess exceeded deadline")
			}
			if size == outputLimit {
				if e != nil || b.Len() != size {
					t.Fatal("exact subprocess boundary refused", b.Len(), e)
				}
			} else if e == nil || b.Len() > outputLimit {
				t.Fatalf("actual subprocess copy bypassed output bound: retained=%d error=%v", b.Len(), e)
			}
		})
	}
}
func TestBoundedOutputChild(t *testing.T) {
	raw := os.Getenv("TASK11_AUDIT_OUTPUT_BYTES")
	if raw == "" {
		return
	}
	n, e := strconv.Atoi(raw)
	if e != nil || n < outputLimit || n > outputLimit*3 {
		os.Exit(2)
	}
	// Both inherited descriptors use the same os/exec pipe, as in units().
	payload := strings.Repeat("x", n)
	split := len(payload) / 2
	if _, e = os.Stdout.WriteString(payload[:split]); e != nil {
		os.Exit(3)
	}
	if _, e = os.Stderr.WriteString(payload[split:]); e != nil {
		os.Exit(4)
	}
	os.Exit(0)
}
