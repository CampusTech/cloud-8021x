package main

import (
	"strings"
	"testing"
)

func TestRecoveryIsBoundToRetainedFleetWorkAndNeverRepublishes(t *testing.T) {
	pin := strings.Repeat("a", 64)
	for _, r := range []recoveryRequest{{Kind: "outbox-republish", Work: "auth:real", Generation: 1, ApplicationSHA256: pin, PayloadSHA256: pin, RequestID: pin}, {Kind: "green-work", Work: "fleet-cert:real", ApplicationSHA256: pin, PayloadSHA256: pin, RequestID: pin}, {Kind: "retained-legacy", Guard: pin, Work: "extra", ApplicationSHA256: pin}} {
		if _, err := recoveryCommand(r); err == nil {
			t.Fatal("unsafe recovery accepted")
		}
	}
	for _, r := range []recoveryRequest{{Kind: "retained-legacy", Guard: pin, ApplicationSHA256: pin}, {Kind: "green-work", Work: "fleet-cert:actual", Generation: 3, PayloadSHA256: pin, RequestID: pin, ApplicationSHA256: pin}} {
		argv, err := recoveryCommand(r)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.Join(argv, " "), "republish") {
			t.Fatal("recovery may resubmit")
		}
	}
}

func TestWindowsRecoveryPassesOnlyOneBoundedUntrustedExecutionHint(t *testing.T) {
	pin := strings.Repeat("a", 64)
	r := recoveryRequest{Kind: "green-work", Work: "fleet-cert:actual", Generation: 1, PayloadSHA256: pin, RequestID: pin, ApplicationSHA256: pin, ExecutionID: "remote-execution-actual"}
	argv, err := recoveryCommand(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(argv, " "), "--execution-id remote-execution-actual") {
		t.Fatal("shipping recovery loses learned execution hint")
	}
	for _, bad := range []string{"a,b", "--flag", "a\nb", strings.Repeat("x", 254)} {
		r.ExecutionID = bad
		if _, err = recoveryCommand(r); err == nil {
			t.Fatal("unbounded or multi-target hint accepted")
		}
	}
}
