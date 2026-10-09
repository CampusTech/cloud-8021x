package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestChildBoundsWithholdPrivateOutputAndHonorDeadline(t *testing.T) {
	raw, err := runBounded(context.Background(), []string{"/usr/bin/printf", "private-token"}, nil, 100, time.Second)
	if err != nil || string(raw) != "private-token" {
		t.Fatalf("bounded child: %v", err)
	}
	raw, err = runBounded(context.Background(), []string{"/usr/bin/printf", "private-token"}, nil, 1, time.Second)
	if err == nil || raw != nil || strings.Contains(err.Error(), "private-token") {
		t.Fatal("overflow leaked private output")
	}
	start := time.Now()
	if _, err = runBounded(context.Background(), []string{"/bin/sleep", "2"}, nil, 10, 20*time.Millisecond); err == nil || time.Since(start) > time.Second {
		t.Fatal("child deadline not enforced")
	}
	if _, err = boundedInput(strings.NewReader("123"), 2); err == nil {
		t.Fatal("unbounded private stdin")
	}
	for _, node := range nodes {
		role := roleOf(node)
		if role != "radius-primary" && role != "radius-secondary" {
			t.Fatal("unknown physical role")
		}
	}
}
