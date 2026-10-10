package host

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/adapters/freeradius/native"
)

func TestCompanionRestartNeverLeavesListeningRadiusWithUnavailablePolicy(t *testing.T) {
	active := true
	policy := false
	events := []string{}
	b := &RadiusBackend{caHealth: func(context.Context) error { return nil }, quiescent: func() error { return nil }, Local: "10.0.0.1", Peer: "10.0.0.2", Companions: true}
	b.status = func(context.Context, string, []byte) error { return nil }
	b.readiness = func(_ context.Context, url string, _ []byte, _ native.Readiness) error {
		if strings.Contains(url, "10.0.0.2") {
			return nil
		}
		if active {
			t.Error("RADIUS listening during policy replacement")
		}
		policy = true
		return nil
	}
	b.run = func(_ context.Context, path string, args ...string) ([]byte, error) {
		event := strings.Join(args, " ")
		events = append(events, event)
		if strings.HasPrefix(event, "show ") {
			if active {
				return []byte("ActiveState=active\nSubState=running\nMainPID=22\n"), nil
			}
			return []byte("ActiveState=inactive\nSubState=dead\nMainPID=0\n"), nil
		}
		if event == "stop freeradius.service" {
			active = false
		}
		if event == "restart cloud-8021x.service" && active {
			t.Error("restarted policy before stopping RADIUS")
		}
		if event == "start freeradius.service" {
			if !policy {
				t.Error("RADIUS started without local policy readiness")
			}
			active = true
		}
		if event == "restart freeradius.service" {
			return nil, errors.New("unexpected direct restart")
		}
		return nil, nil
	}
	cleanup := false
	b.AuthCleanup = func(context.Context) error {
		if active {
			t.Fatal("cleanup before native producer stopped")
		}
		cleanup = true
		return nil
	}
	if e := b.Activate(context.Background()); e != nil {
		t.Fatal(e)
	}
	if !active || !policy || !cleanup {
		t.Fatalf("activation incomplete %v", events)
	}
}

func TestStoppedServiceRequiresIndependentListenerQuiescence(t *testing.T) {
	b := &RadiusBackend{run: func(context.Context, string, ...string) ([]byte, error) {
		return []byte("ActiveState=inactive\nSubState=dead\nMainPID=0\n"), nil
	}, quiescent: func() error { return errors.New("authentication listener still bound") }}
	if _, err := b.Running(context.Background()); err == nil {
		t.Fatal("accepted inactive service with live listener")
	}
	b.quiescent = func() error { return nil }
	if running, err := b.Running(context.Background()); err != nil || running {
		t.Fatalf("proven stopped: %v %v", running, err)
	}
}

func TestCompanionFailureKeepsNativeStoppedAndBarrierHeld(t *testing.T) {
	active := true
	released := false
	b := &RadiusBackend{Companions: true, Local: "10.0.0.1", Peer: "10.0.0.2", quiescent: func() error { return nil }, status: func(context.Context, string, []byte) error { return nil }, readiness: func(context.Context, string, []byte, native.Readiness) error { return nil }, caHealth: func(context.Context) error { return nil }}
	b.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		action := strings.Join(args, " ")
		if strings.HasPrefix(action, "show ") {
			if active {
				return []byte("ActiveState=active\nMainPID=22\n"), nil
			}
			return []byte("ActiveState=inactive\nSubState=dead\nMainPID=0\n"), nil
		}
		if action == "stop freeradius.service" {
			active = false
		}
		if action == "start freeradius.service" {
			active = true
		}
		return nil, nil
	}
	b.releaseBarrier = func(context.Context) error { released = true; return nil }
	b.collectorStart = func(context.Context) error { return errors.New("collector activation unavailable") }
	if e := b.Activate(context.Background()); e == nil || active || released {
		t.Fatal("failure exposed native listener or released barrier", e)
	}
	b.collectorStart = func(context.Context) error {
		if active {
			t.Fatal("native started ahead of collector")
		}
		return nil
	}
	if e := b.Activate(context.Background()); e != nil || !active || !released {
		t.Fatal("readiness did not release barrier/start", e)
	}
}
