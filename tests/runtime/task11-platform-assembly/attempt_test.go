package main

import (
	"os"
	"testing"
)

func TestInterruptedAttemptNeverAutomaticallyReplays(t *testing.T) {
	d := protectedPlatformFixture(t)
	p := d + "/attempt.json"
	if e := beginAttempt(p, "assemble", "original"); e != nil {
		t.Fatal(e)
	}
	if e := beginAttempt(p, "assemble", "original"); e == nil {
		t.Fatal("interrupted operation replayed")
	}
	b, _ := os.ReadFile(p)
	if string(b) != "{\"stage\":\"assemble\",\"plan_sha256\":\"original\"}\n" {
		t.Fatal("attempt identity changed")
	}
}
