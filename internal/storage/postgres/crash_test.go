package postgres

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
	"github.com/CampusTech/cloud-8021x/internal/config"
)

// This helper exits the actual test process without running cleanup/rollback.
func TestPostgresCrashHelper(t *testing.T) {
	phase := os.Getenv("C8021X_PG_CRASH_PHASE")
	if phase == "" {
		return
	}
	c := config.Defaults().Database
	c.CAFile = os.Getenv("C8021X_PG_TEST_CA")
	s, err := New(context.Background(), roleDSN(t, "app_runtime", "disposable-runtime"), c)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result, err := processLocked(context.Background(), tx, testKey, binding.MaxAge)
	if err != nil || result.UsageID == "" {
		t.Fatal(result, err)
	}
	if phase == "after" {
		if err = commit(context.Background(), tx); err != nil {
			t.Fatal(err)
		}
	}
	os.Exit(42)
}
func TestPostgresActualProcessDeathBeforeAndAfterCommit(t *testing.T) {
	admin, c := integration(t)
	s := runtimeStore(t, admin, c)
	ctx := context.Background()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"before", "after"} {
		t.Run(phase, func(t *testing.T) {
			reset(t, admin)
			for _, status := range []string{"Start", "Interim-Update"} {
				if err := insertRaw(ctx, s, testRaw("process-death", status)); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.ProcessOne(ctx, testKey, binding.MaxAge); err != nil {
				t.Fatal(err)
			}
			child := exec.Command(executable, "-test.run=^TestPostgresCrashHelper$")
			child.Env = append(os.Environ(), "C8021X_PG_CRASH_PHASE="+phase)
			output, err := child.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 42 {
				t.Fatalf("crash helper failed: %v %s", err, output)
			}
			result, err := s.ResolveIntake(ctx, 2)
			if err != nil || result.Processed != (phase == "after") {
				t.Fatal("wrong crash commit state", result, err)
			}
			if err = drain(ctx, s); err != nil {
				t.Fatal(err)
			}
			if count(t, admin, "observations") != 2 || count(t, admin, "intervals") != 1 || count(t, admin, "work") != 3 {
				t.Fatal("process death lost or duplicated work")
			}
		})
	}
}
