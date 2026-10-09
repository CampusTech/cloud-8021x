package migration

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const baselineCheckpoint = `{"version":2,"phase":"baseline","tracker":{"version":1,"sessions":[]},"through":1791374300,"credit_start":1791374400,"pending":[],"uncertain":false,"seeded":false,"preview_id":null}`

func TestLegacyBaselineStrictRoundTrip(t *testing.T) {
	c, err := DecodeUsage([]byte(baselineCheckpoint), []string{"radius-primary"})
	if err != nil {
		t.Fatal("valid interrupted baseline refused:", err)
	}
	out, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, exact := range []string{`"version":2`, `"phase":"baseline"`, `"through":1791374300`, `"credit_start":1791374400`} {
		if !bytes.Contains(out, []byte(exact)) {
			t.Fatalf("lost original baseline evidence %s: %s", exact, out)
		}
	}
}

func TestLegacyBaselineRejectsInvalidStates(t *testing.T) {
	for _, change := range [][2]string{
		{`"baseline"`, `"credit"`}, {`"phase":"baseline",`, ``}, {`"baseline"`, `null`},
		{`"through":1791374300`, `"through":1791374400`}, {`"through":1791374300`, `"through":1791374401`},
		{`"through":1791374300`, `"through":null`}, {`"credit_start":1791374400`, `"credit_start":null`},
		{`"credit_start":1791374400`, `"credit_start":true`}, {`"credit_start":1791374400,`, ``},
		{`"pending":[]`, `"pending":[{}]`}, {`"uncertain":false`, `"uncertain":true`}, {`"seeded":false`, `"seeded":true`},
		{`"version":2`, `"version":1`}, {`"version":2`, `"version":3`},
	} {
		input := strings.Replace(baselineCheckpoint, change[0], change[1], 1)
		if _, err := DecodeUsage([]byte(input), []string{"radius-primary"}); err == nil {
			t.Fatalf("accepted invalid baseline %s", input)
		}
	}
}

// Real Python interruption -> Go decode/export -> real Python restart. This
// catches rounding, reseeding, lost phase/floor, and accidental pre-floor credit.
func TestLegacyBaselinePythonInterruptedRestartParity(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("Python development parity dependency required:", err)
	}
	state := filepath.Join(t.TempDir(), "checkpoint.json")
	fixture := filepath.Join("..", "..", "tests", "legacy", "baseline_checkpoint.py")
	run := func(action string) {
		t.Helper()
		if out, err := exec.Command(python, fixture, action, state).CombinedOutput(); err != nil {
			t.Fatalf("Python %s: %v\n%s", action, err, out)
		}
	}
	run("interrupt")
	raw, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	c, err := DecodeUsage(raw, []string{"radius-primary", "radius-secondary"})
	if err != nil {
		t.Fatal("deployed Python baseline refused:", err)
	}
	if len(c.Tracker.Sessions) != 1 || c.Tracker.Sessions[0].Upload <= 1<<53 {
		t.Fatal("fixture did not preserve large counters")
	}
	out, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(state, out, 0600); err != nil {
		t.Fatal(err)
	}
	run("resume")
}
