package app

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
)

func TestParallelRenewalAuthCleanupRejectsUnprovenGeneration(t *testing.T) {
	backend := &host.RadiusBackend{}
	rollbackBackend := *backend
	setParallelRenewalAuthCleanup(backend, "radius-primary", "", strings.Repeat("a", 32), host.Accounts{}, nil)
	if backend.AuthCleanup == nil {
		t.Fatal("renewal activation has no guarded auth cleanup callback")
	}
	// Execute the production callback through the real protected host boundary.
	// An unknown replacement must fail before native inspection or cursor access.
	err := backend.AuthCleanup(context.Background())
	if err == nil || !strings.Contains(err.Error(), "root exact generation cleanup required") {
		t.Fatalf("renewal cleanup lost the exact-generation guard: %v", err)
	}
	if rollbackBackend.AuthCleanup != nil {
		t.Fatal("failed renewal cleanup contaminated the rollback backend")
	}
}

func TestParallelRenewalAuthCleanupPropagatesUnprovenStop(t *testing.T) {
	backend := &host.RadiusBackend{}
	setParallelRenewalAuthCleanup(backend, "radius-primary", strings.Repeat("b", 32), strings.Repeat("a", 32), host.Accounts{}, nil)
	if backend.AuthCleanup == nil {
		t.Fatal("renewal activation has no guarded auth cleanup callback")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Cancellation prevents an observation of a stopped native service. On
	// unprivileged platforms the earlier root guard prevents host access entirely.
	want := "native stop not proven"
	if os.Geteuid() != 0 {
		want = "root exact generation cleanup required"
	}
	err := backend.AuthCleanup(ctx)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("renewal cleanup lost the protected-stop guard: %v", err)
	}
}
