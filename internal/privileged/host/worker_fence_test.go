package host

import "testing"

func TestWorkerFenceIncludesOriginalDescendantsAndOtherCLI(t *testing.T) {
	processes := []writerProcess{{PID: 1, Start: 10, Args: "/usr/local/bin/cloud-8021x\x00serve\x00"}, {PID: 2, Parent: 1, Start: 11, Args: "/bin/sh\x00worker\x00"}, {PID: 3, Start: 12, Args: "/usr/local/bin/cloud-8021x\x00sources\x00apply\x00"}, {PID: 4, Start: 13, Args: "/usr/local/bin/cloud-8021x\x00state\x00export\x00"}}
	got := daemonProcessEvidence(processes, 4)
	if len(got) != 3 {
		t.Fatalf("inflight worker lineage missed: %+v", got)
	}
}
