// Development-only four-node platform assembly. Nothing here supplies product receipts.
package main

import (
	"errors"
	"reflect"
	"regexp"

	seed "github.com/CampusTech/cloud-8021x/tests/runtime/task11-assembly-seed/contract"
)

const platformRoot = "/var/lib/cloud8021x-task11"
const controlRoot = platformRoot + "/control"
const candidateRoot = controlRoot + "/runtime-candidates"
const originalRoot = controlRoot + "/original-seed"
const MiB int64 = 1 << 20
const GiB int64 = 1 << 30

type pin struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type node struct{ Name, Namespace, Address, MachineID string }
type flow struct {
	Source, Destination, Protocol string
	Port                          int
}
type budget struct{ SourceBytes, LowerBytes, StagingBytes, PrivateBytes, Inodes, FreeBytes, FreeInodes int64 }
type plan struct {
	Schema                                                                                   int
	InputSHA256, CandidateSHA256, PackageManifestSHA256, BaselineSHA256, LowerManifestSHA256 string
	ApplicationSourceSHA, ApplicationSHA256, ControllerSHA256, ObserverSHA256, CloudSHA256   string
	ObserverSourceSHA256, CloudSourceSHA256, PrimitiveSeedSHA256, PrimitiveExpectedSHA256    string
	ControllerUnitSHA256, PrimitiveInputSHA256, BluePlanSHA256                               string
	Helpers                                                                                  map[string]pin
	Tools                                                                                    map[string]pin
	Nodes                                                                                    []node
	Flows                                                                                    []flow
	Budget                                                                                   budget
	LoopDevices                                                                              []string
}

func fixedNodes() []node {
	return []node{{"blue-primary", "c11-bp", "10.203.11.31", ""}, {"blue-secondary", "c11-bs", "10.203.11.32", ""}, {"green-primary", "c11-gp", "10.203.11.21", ""}, {"green-secondary", "c11-gs", "10.203.11.22", ""}}
}
func fixedFlows() []flow {
	var out []flow
	for _, n := range fixedNodes() {
		out = append(out, flow{n.Address, "10.203.11.10", "tcp", 443}, flow{n.Address, "10.203.11.11", "tcp", 5432})
		for _, port := range []int{1812, 1813} {
			out = append(out, flow{"10.203.11.40", n.Address, "udp", port})
		}
		for _, port := range []int{8443, 8444, 9081} {
			out = append(out, flow{"10.203.11.40", n.Address, "tcp", port})
		}
	}
	for _, pair := range [][2]string{{"10.203.11.21", "10.203.11.22"}, {"10.203.11.31", "10.203.11.32"}} {
		for _, p := range [][2]string{pair, {pair[1], pair[0]}} {
			out = append(out, flow{p[0], p[1], "udp", 18121}, flow{p[0], p[1], "tcp", 18122})
		}
	}
	return out
}

var sha40 = regexp.MustCompile(`^[0-9a-f]{40}$`)
var machineID = regexp.MustCompile(`^[0-9a-f]{32}$`)

const publicRoot = controlRoot + "/public"

var helperNames = []string{"task11-acceptance", "task11-passive-audit", "task11-cloud-contract", "task11-assembly-seed", "task11-blue-migration", "task11-systemd-fixture"}
var toolPaths = map[string]string{"ip": "/usr/sbin/ip", "nft": "/usr/sbin/nft", "mount": "/usr/bin/mount", "umount": "/usr/bin/umount", "mkfs": "/usr/sbin/mke2fs", "fallocate": "/usr/bin/fallocate", "chroot": "/usr/sbin/chroot", "systemctl": "/usr/bin/systemctl", "systemd-run": "/usr/bin/systemd-run", "nspawn": "/usr/bin/systemd-nspawn", "dpkg-query": "/usr/bin/dpkg-query", "dpkg": "/usr/bin/dpkg", "losetup": "/usr/sbin/losetup", "sysctl": "/usr/sbin/sysctl"}

func (p plan) validate() error {
	if p.Schema != 1 || !sha40.MatchString(p.ApplicationSourceSHA) {
		return errors.New("complete platform plan required")
	}
	for _, v := range []string{p.InputSHA256, p.CandidateSHA256, p.PackageManifestSHA256, p.BaselineSHA256, p.LowerManifestSHA256, p.ApplicationSHA256, p.ControllerSHA256, p.ObserverSHA256, p.CloudSHA256, p.ObserverSourceSHA256, p.CloudSourceSHA256, p.PrimitiveSeedSHA256, p.PrimitiveExpectedSHA256, p.ControllerUnitSHA256, p.PrimitiveInputSHA256, p.BluePlanSHA256} {
		if !seed.IsSHA(v) {
			return errors.New("independent platform pin absent")
		}
	}
	fixed := fixedNodes()
	if len(p.Nodes) != len(fixed) || !reflect.DeepEqual(p.Flows, fixedFlows()) {
		return errors.New("closed topology differs")
	}
	seen := map[string]bool{}
	for i, n := range p.Nodes {
		if n.Name != fixed[i].Name || n.Namespace != fixed[i].Namespace || n.Address != fixed[i].Address || !machineID.MatchString(n.MachineID) || seen[n.MachineID] {
			return errors.New("distinct exact physical nodes required")
		}
		seen[n.MachineID] = true
	}
	if len(p.Helpers) != len(helperNames) || len(p.Tools) != len(toolPaths) {
		return errors.New("complete independently pinned executables required")
	}
	for _, n := range helperNames {
		v := p.Helpers[n]
		if v.Path != publicRoot+"/"+n || !seed.IsSHA(v.SHA256) {
			return errors.New("helper identity differs")
		}
	}
	for n, path := range toolPaths {
		v := p.Tools[n]
		if v.Path != path || !seed.IsSHA(v.SHA256) {
			return errors.New("tool identity differs")
		}
	}
	if p.Helpers["task11-acceptance"].SHA256 != p.ControllerSHA256 || p.Helpers["task11-passive-audit"].SHA256 != p.ObserverSHA256 || p.Helpers["task11-cloud-contract"].SHA256 != p.CloudSHA256 || p.CloudSHA256 != "e6c0a5373ca718e17cf288f28095223c67dbfefa88461233ed1660ec2d5fd0d4" {
		return errors.New("reviewed helper binding differs")
	}
	if len(p.LoopDevices) != 2 || p.LoopDevices[0] == p.LoopDevices[1] {
		return errors.New("two distinct measured loop devices required")
	}
	for _, d := range p.LoopDevices {
		if !regexp.MustCompile(`^/dev/loop[0-9]{1,3}$`).MatchString(d) {
			return errors.New("unapproved loop device")
		}
	}
	return p.Budget.validate()
}

// These are allocated filesystem ceilings, not success observations. Public
// per-file binds avoid charging incoming archives to each private overlay.
const backingBytes = 2*768*MiB + 2*256*MiB + 256*MiB + 128*MiB + 64*MiB

func (b budget) validate() error {
	if b.SourceBytes <= 0 || b.SourceBytes > 1536*MiB || b.LowerBytes < b.SourceBytes || b.LowerBytes > 1792*MiB || b.StagingBytes <= 0 || b.StagingBytes > 512*MiB || b.PrivateBytes <= 0 || b.PrivateBytes > 128*MiB || b.Inodes <= 0 || b.Inodes > 200000 {
		return errors.New("measured copy/private footprint outside reviewed caps")
	}
	// Source measured after347; lower maximum includes exact62 genuine installation.
	// Staging/private inputs are already present when actual statfs is sampled;
	// charging them again would not describe the remaining allocation.
	required := 1792*MiB + backingBytes + GiB
	if b.FreeBytes < required || b.FreeInodes < b.Inodes+100000 {
		return errors.New("measured capacity cannot preserve lower, private filesystems and free reserve")
	}
	return nil
}
