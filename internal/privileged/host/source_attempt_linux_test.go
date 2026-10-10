package host

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestInstalledSourceOriginalHelperQuiescence(t *testing.T) {
	if os.Getenv("C8021X_WRITER_FIXTURE") != "task9" {
		t.Skip("owned Linux source fixture")
	}
	operation := "sources-apply:" + strings.Repeat("f", 64)
	if os.Getenv("C8021X_SOURCE_CHILD") == "task9" {
		unlock, e := AcquireWriterOperation()
		if e != nil {
			t.Fatal(e)
		}
		defer unlock()
		if e = PrepareSourceAttempt(operation, 91); e != nil {
			t.Fatal(e)
		}
		if e = ProveSourceAttemptStopped(operation, 91); e == nil {
			t.Fatal("active original helper accepted")
		}
		if release, e := AcquireWriterOperation(); e == nil {
			release()
			t.Fatal("original flock contention ignored")
		}
		return
	}
	child := exec.CommandContext(context.Background(), os.Args[0], "-test.run=^TestInstalledSourceOriginalHelperQuiescence$")
	child.Env = append(os.Environ(), "C8021X_SOURCE_CHILD=task9")
	if out, e := child.CombinedOutput(); e != nil {
		t.Fatal(e, string(out))
	}
	unlock, e := AcquireWriterOperation()
	if e != nil {
		t.Fatal(e)
	}
	defer unlock()
	if e = ProveSourceAttemptStopped(operation, 91); e != nil {
		t.Fatal(e)
	}
	if e = ProveSourceAttemptStopped(operation, 92); e == nil {
		t.Fatal("different journal attempt accepted")
	}
	if e = ProveSourceAttemptStopped("sources-apply:"+strings.Repeat("e", 64), 91); e == nil {
		t.Fatal("different work binding accepted")
	}
}
