package app

import (
	"bytes"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/config"
)

func TestRootOperationsRejectAlternateConfigBeforeParsing(t *testing.T) {
	for _, args := range [][]string{{"bootstrap"}, {"certificates", "renew"}, {"sources", "apply"}} {
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

func TestBootstrapDryRunRequiresNoCredentialFilesOrRemoteCalls(t *testing.T) {
	cfg, e := config.Load("../../examples/cloud-8021x.yaml")
	if e != nil {
		t.Fatal(e)
	}
	var output bytes.Buffer
	// Exercise the pure plan on every platform; root fixed-path parsing has its
	// separate pre-parse rejection test and actual installed Linux fixture.
	if e = bootstrapPlan(cfg, RunOptions{DryRun: true, Output: &output}, false); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(output.String(), "shared-maintenance") {
		t.Fatal("no reviewable operation plan")
	}
}
