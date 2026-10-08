package host

import (
	"context"
	"errors"
	"testing"
)

type activationFixture struct {
	events                                  []string
	active                                  bool
	peerError, validateError, activateError bool
}

func (f *activationFixture) Running(context.Context) (bool, error) {
	f.events = append(f.events, "running")
	return f.active, nil
}
func (f *activationFixture) PeerReady(context.Context) error {
	f.events = append(f.events, "peer")
	if f.peerError {
		return errors.New("not ready")
	}
	return nil
}
func (f *activationFixture) Validate(context.Context) error {
	f.events = append(f.events, "validate")
	if f.validateError {
		return errors.New("invalid")
	}
	return nil
}
func (f *activationFixture) Activate(context.Context) error {
	f.events = append(f.events, "activate")
	if f.activateError {
		return errors.New("failed")
	}
	return nil
}
func (f *activationFixture) Healthy(context.Context) error {
	f.events = append(f.events, "healthy")
	return nil
}
func TestActivationRequiresReadyPeerOnlyForRunningNode(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(map[bool]string{false: "stopped", true: "running"}[active], func(t *testing.T) {
			f := &activationFixture{active: active, peerError: true}
			if e := CheckRestart(context.Background(), f); (e == nil) == active {
				t.Fatalf("active %v error %v", active, e)
			}
		})
	}
}
func TestInvalidCandidateCannotRestart(t *testing.T) {
	f := &activationFixture{active: true, validateError: true}
	if e := ActivateValidated(context.Background(), f); e == nil {
		t.Fatal("accepted invalid config")
	}
	for _, event := range f.events {
		if event == "activate" {
			t.Fatal("restarted invalid config")
		}
	}
}
