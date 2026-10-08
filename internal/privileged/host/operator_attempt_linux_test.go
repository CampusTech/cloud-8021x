package host

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestInstalledOperatorOriginalHelper(t *testing.T) {
	if os.Getenv("C8021X_WRITER_FIXTURE") != "task9" {
		t.Skip("owned Linux fixture")
	}
	id, hash := strings.Repeat("d", 64), strings.Repeat("e", 64)
	if os.Getenv("C8021X_OPERATOR_CHILD") == "task9" {
		release, e := AcquireWriterOperation()
		if e != nil {
			t.Fatal(e)
		}
		defer release()
		if e = PrepareOperatorAttempt(id, hash, 91, []byte(`{"original":"work"}`)); e != nil {
			t.Fatal(e)
		}
		if _, e = ProveOperatorAttemptStopped(id, hash, 91); e == nil {
			t.Fatal("live original helper accepted")
		}
		return
	}
	child := exec.Command(os.Args[0], "-test.run=^TestInstalledOperatorOriginalHelper$")
	child.Env = append(os.Environ(), "C8021X_OPERATOR_CHILD=task9")
	if out, e := child.CombinedOutput(); e != nil {
		t.Fatal(e, string(out))
	}
	release, e := AcquireWriterOperation()
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	if _, e = ProveOperatorAttemptStopped(id, hash, 91); e != nil {
		t.Fatal(e)
	}
	if _, e = ProveOperatorAttemptStopped(id, hash, 92); e == nil {
		t.Fatal("foreign attempt accepted")
	}
	if _, e = ProveOperatorAttemptStopped(id, strings.Repeat("f", 64), 91); e == nil {
		t.Fatal("foreign payload accepted")
	}
	if e = PrepareOperatorAttempt(id, hash, 92, []byte(`{"original":"work"}`)); e == nil {
		t.Fatal("original helper overwritten")
	}
}
