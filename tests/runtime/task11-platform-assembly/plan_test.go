package main

import (
	"fmt"
	"strings"
	"testing"
)

func validPlan() plan {
	s := strings.Repeat("a", 64)
	p := plan{Schema: 1, InputSHA256: s, CandidateSHA256: s, PackageManifestSHA256: s, BaselineSHA256: s, LowerManifestSHA256: s, ApplicationSourceSHA: strings.Repeat("a", 40), ApplicationSHA256: s, ControllerSHA256: s, ObserverSHA256: s, CloudSHA256: s, ObserverSourceSHA256: s, CloudSourceSHA256: s, PrimitiveSeedSHA256: s, PrimitiveExpectedSHA256: s, ControllerUnitSHA256: s, PrimitiveInputSHA256: s, BluePlanSHA256: s, Helpers: map[string]pin{}, Tools: map[string]pin{}, Nodes: fixedNodes(), Flows: fixedFlows(), Budget: budget{SourceBytes: GiB, LowerBytes: 1500 * MiB, StagingBytes: 300 * MiB, PrivateBytes: 64 * MiB, Inodes: 100000, FreeBytes: 7 * GiB, FreeInodes: 300000}}
	for i := range p.Nodes {
		p.Nodes[i].MachineID = fmt.Sprintf("%032x", i+1)
	}
	for _, n := range helperNames {
		p.Helpers[n] = pin{publicRoot + "/" + n, s}
	}
	for n, path := range toolPaths {
		p.Tools[n] = pin{path, s}
	}
	p.CloudSHA256 = "e6c0a5373ca718e17cf288f28095223c67dbfefa88461233ed1660ec2d5fd0d4"
	p.Helpers["task11-cloud-contract"] = pin{publicRoot + "/task11-cloud-contract", p.CloudSHA256}
	p.LoopDevices = []string{"/dev/loop8", "/dev/loop9"}
	return p
}
func TestRejectChangedTopologyPinsAndInsufficientResources(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*plan)
	}{
		{"node", func(p *plan) { p.Nodes[0].Name = "production" }},
		{"namespace", func(p *plan) { p.Nodes[0].Namespace = "host" }},
		{"IP", func(p *plan) { p.Nodes[0].Address = "192.168.1.1" }},
		{"shared-machine", func(p *plan) { p.Nodes[0].MachineID = p.Nodes[1].MachineID }},
		{"default-route", func(p *plan) { p.Flows[0].Destination = "0.0.0.0/0" }},
		{"source-spoof", func(p *plan) { p.Flows[0].Source = "10.203.11.40" }},
		{"port", func(p *plan) { p.Flows[0].Port = 22 }},
		{"missing-pin", func(p *plan) { p.InputSHA256 = "" }},
		{"source-too-large", func(p *plan) { p.Budget.SourceBytes = 2 * GiB }},
		{"no-free-reserve", func(p *plan) { p.Budget.FreeBytes = 2 * GiB }},
		{"inode-shortage", func(p *plan) { p.Budget.FreeInodes = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := validPlan()
			tc.change(&p)
			if p.validate() == nil {
				t.Fatal("unsafe platform plan accepted")
			}
		})
	}
}

func TestMeasuredBoundedPlanAccepted(t *testing.T) {
	if err := validPlan().validate(); err != nil {
		t.Fatal(err)
	}
}
