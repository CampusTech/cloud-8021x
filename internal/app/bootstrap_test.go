package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/config"
)

func TestRootOperationsRejectAlternateConfigBeforeParsing(t *testing.T) {
	for _, args := range [][]string{{"bootstrap", "prepare"}, {"certificates", "renew"}, {"sources", "apply"}} {
		cmd := NewCommand(Options{ProcessUID: func() int { return 0 }})
		cmd.SetArgs(append(args, "--config", "/tmp/not-protected.yaml"))
		cmd.SetOut(new(bytes.Buffer))
		cmd.SetErr(new(bytes.Buffer))
		e := cmd.Execute()
		if e == nil || !strings.Contains(e.Error(), "fixed protected") {
			t.Fatalf("%v error=%v", args, e)
		}
	}
}

func TestRenewalDryRunRequiresNoCredentialFilesOrRemoteCalls(t *testing.T) {
	cfg, e := config.Load("../../examples/cloud-8021x.yaml")
	if e != nil {
		t.Fatal(e)
	}
	var output bytes.Buffer
	// Exercise the pure plan on every platform; root fixed-path parsing has its
	// separate pre-parse rejection test and actual installed Linux fixture.
	if e = renewalPlan(cfg, RunOptions{DryRun: true, Output: &output}); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(output.String(), "shared-maintenance") {
		t.Fatal("no reviewable operation plan")
	}
}

type closedBootstrapOutput struct{}

func (closedBootstrapOutput) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestBootstrapOutputFailureDoesNotFailMaintenance(t *testing.T) {
	complete, rolledBack := false, false
	gate := func(ctx context.Context, _ string, action func(context.Context) error) error {
		if e := action(ctx); e != nil {
			return errors.New("journal marked uncertain")
		}
		complete = true
		return nil
	}
	e := withBootstrapReport(context.Background(), gate, "bootstrap", closedBootstrapOutput{}, func(_ context.Context, outcome *bootstrapOutcome) (result error) {
		defer func() {
			if result != nil {
				rolledBack = true
			}
		}()
		outcome.Changed = true
		outcome.Installation = strings.Repeat("a", 32)
		return nil
	})
	if !complete || rolledBack || !errors.Is(e, io.ErrClosedPipe) {
		t.Fatalf("output failure contaminated committed maintenance: complete=%v error=%v", complete, e)
	}
}

func TestBootstrapUncertainGateDoesNotReportCompletion(t *testing.T) {
	var output bytes.Buffer
	uncertain := errors.New("maintenance completion uncertain")
	gate := func(ctx context.Context, _ string, action func(context.Context) error) error {
		if e := action(ctx); e != nil {
			return e
		}
		return uncertain
	}
	attempts := 0
	e := withBootstrapReport(context.Background(), gate, "bootstrap", &output, func(_ context.Context, outcome *bootstrapOutcome) error {
		attempts++
		outcome.Changed = true
		return nil
	})
	if !errors.Is(e, uncertain) || output.Len() != 0 || attempts != 1 {
		t.Fatalf("uncertain completion retried/reported: attempts=%d output=%q error=%v", attempts, output.String(), e)
	}
}
