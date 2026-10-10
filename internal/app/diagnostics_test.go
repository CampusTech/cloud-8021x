package app

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/config"
)

func TestDiagnosticsDryRunHasNoCredentialOrNetworkDependency(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root requires fixed protected config; covered by isolated installed fixture")
	}
	cfg, err := config.Load("../../examples/cloud-8021x.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []Operation{OperationDoctor, OperationMetricsEmit} {
		var out bytes.Buffer
		if err := NewRuntimeServices().Run(context.Background(), op, cfg, RunOptions{DryRun: true, Output: &out}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "postgres") || strings.Contains(out.String(), "password") {
			t.Fatal(out.String())
		}
	}
}
