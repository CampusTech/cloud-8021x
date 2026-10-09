package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/app"
)

// The actual shipping parser/root guard must select its incoming reader. This
// host-side test deliberately has no Services and creates no fixed root files.
func TestGeneratedStagedArgvPassesActualShippingRootGuard(t *testing.T) {
	for _, op := range []string{"source-key", "capture", "prepare", "resume-source"} {
		t.Run(op, func(t *testing.T) {
			argv, err := shippingCommand(op)
			if err != nil {
				t.Fatal(err)
			}
			cmd := app.NewCommand(app.Options{ProcessUID: func() int { return 0 }})
			cmd.SetOut(new(bytes.Buffer))
			cmd.SetErr(new(bytes.Buffer))
			cmd.SetArgs(argv[1:])
			err = cmd.Execute()
			if err == nil {
				t.Fatal("no mutation services should run")
			}
			if strings.Contains(err.Error(), "root operation requires the fixed protected application configuration") {
				t.Fatalf("generated staged argv rejected by actual root guard: %v", err)
			}
			// The next boundary is the protected reader (or unavailable Services if a
			// real protected fixture is present), not an unknown flag/subcommand.
			if !strings.Contains(err.Error(), "configuration") && !strings.Contains(err.Error(), "unsupported") {
				t.Fatalf("unexpected actual CLI boundary: %v", err)
			}
		})
	}
}

func TestGeneratedRecoveryArgvPassesActualShippingParser(t *testing.T) {
	pin := strings.Repeat("a", 64)
	for _, request := range []recoveryRequest{{Kind: "retained-legacy", Guard: pin, ApplicationSHA256: pin}, {Kind: "green-work", Work: "fleet-cert:actual-original", Generation: 7, PayloadSHA256: pin, RequestID: pin, ApplicationSHA256: pin, ExecutionID: "remote-execution-actual"}} {
		argv, err := recoveryCommand(request)
		if err != nil {
			t.Fatal(err)
		}
		cmd := app.NewCommand(app.Options{ProcessUID: func() int { return 0 }})
		cmd.SetOut(new(bytes.Buffer))
		cmd.SetErr(new(bytes.Buffer))
		cmd.SetArgs(argv[1:])
		err = cmd.Execute()
		if err == nil {
			t.Fatal("no installed root services should run")
		}
		if strings.Contains(err.Error(), "unknown") || strings.Contains(err.Error(), "root operation requires") {
			t.Fatalf("real parser refused generated recovery: %v", err)
		}
	}
}
