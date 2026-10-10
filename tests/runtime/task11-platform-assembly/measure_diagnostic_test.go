package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"testing"
)

func TestMeasureBaseReportsActualGuardFailure(t *testing.T) {
	if os.Getenv("TASK11_MEASURE_GUARD_DIAGNOSTIC") == "1" {
		os.Args = []string{"task11-platform-assembly", "measure-base"}
		main()
		return
	}
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		t.Skip("This guard-only diagnostic uses a non-root or non-Linux test process")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestMeasureBaseReportsActualGuardFailure$")
	child.Env = append(os.Environ(), "TASK11_MEASURE_GUARD_DIAGNOSTIC=1")
	output, err := child.CombinedOutput()
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.ExitCode() != 1 {
		t.Fatalf("expected guard refusal exit1: %v", err)
	}
	if !bytes.Contains(output, []byte("actual isolated Linux root required")) {
		t.Fatalf("measurement swallowed its actual public guard failure: %s", output)
	}
}
