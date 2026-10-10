package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting"
	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

func TestUnenrolledDriverRequiresAuthenticatedRejectAndEmptyBeforeAfter(t *testing.T) {
	p := pureNASPlan()
	p.Scenario.Scenario = "eap-unenrolled"
	p.Scenario.Case = "eap-unenrolled"
	p.Scenario.Session = "task11-eap-unenrolled"
	p.Scenario.Events = nil
	a := outerAttempt{Schema: 1, Case: p.Scenario.Case, AttemptID: "task11-" + strings.Repeat("1", 32), PlanSHA256: strings.Repeat("9", 64)}
	for _, fault := range []string{"", "missing", "timeout", "accept", "auth", "class", "vlan", "attribution", "ids", "packets", "retired", "pin", "before", "after", "epoch", "probe-retired", "probe-request-pin", "probe-raw", "counts", "fingerprint", "tunnel-type", "tunnel-medium"} {
		t.Run(fault, func(t *testing.T) {
			actions := []string{}
			reads := 0
			invoke := func(_ context.Context, r sc.Request) (retiredOperation, error) {
				actions = append(actions, r.Action)
				rq, _ := json.Marshal(r)
				now := p.Scenario.CollectionEpoch.Add(time.Hour)
				op := retiredOperation{request: r, result: sc.Result{Schema: 1, Kind: "scenario-operation", AttemptID: r.AttemptID, Sequence: r.Sequence, Action: r.Action, Pins: r.Pins, RequestSHA256: digestBytes(rq), StartedAt: now, FinishedAt: now.Add(time.Second), Retired: true}}
				switch r.Action {
				case "probe-active-pair":
					op.result.Probe = negativeTestPair(p)
					if fault == "probe-retired" {
						op.result.Retired = false
					}
					if fault == "probe-request-pin" {
						op.result.RequestSHA256 = strings.Repeat("0", 64)
					}
				case "read-accounting":
					reads++
					l := sc.LedgerObservation{Deployment: "task11-green", Database: "cloud8021x_task11_green", Epoch: p.Scenario.CollectionEpoch, ConfigSHA256: strings.Repeat("a", 64), ReadOnly: true, Isolation: "repeatable-read"}
					if fault == "before" && reads == 1 || fault == "after" && reads == 2 {
						l.Sessions = []sc.SessionObservation{{SessionKey: accounting.SessionKey([4]string{p.Scenario.NAS, p.Scenario.NAS, "aabbccddeeff", p.Scenario.Session}), State: accounting.State{Bits: 32}}}
					}
					if fault == "epoch" {
						l.Epoch = l.Epoch.Add(time.Second)
					}
					op.result.Ledger = &l
				case "nas-native":
					n := nativeRejectedBody(p, sc.EAPResult{Rejected: true, ResponseCode: 3, ResponseAuthenticatorSHA256: strings.Repeat("b", 64)}, now)
					switch fault {
					case "missing":
						n = sc.NASResult{}
					case "timeout":
						n.EAP = sc.EAPResult{}
					case "accept":
						n.EAP.Accepted = true
					case "auth":
						n.EAP.ResponseAuthenticatorSHA256 = ""
					case "class":
						n.ClassSHA256 = strings.Repeat("b", 64)
					case "vlan":
						n.EAP.VLAN = 120
					case "counts":
						n.Expected.Seconds = 1
					case "fingerprint":
						n.Attribution.Fingerprint = strings.Repeat("b", 64)
					case "tunnel-type":
						n.EAP.TunnelType = 13
					case "tunnel-medium":
						n.EAP.TunnelMediumType = 6
					case "attribution":
						n.Attribution.DeviceID = "fleet:1"
					case "ids":
						n.Expected.EventIDs = []string{"fabricated"}
					case "packets":
						n.Packets = []sc.AccountingPacketResult{{Status: 1}}
					case "retired":
						op.result.Retired = false
					case "pin":
						op.result.RequestSHA256 = strings.Repeat("0", 64)
					}
					op.result.NAS = &n
				}
				op.raw, _ = json.Marshal(op.result)
				if fault == "probe-raw" && r.Action == "probe-active-pair" {
					op.raw = []byte("{}")
				}
				return op, nil
			}
			operations, e := executeAccountingActions(context.Background(), p, a, invoke)
			if fault == "" {
				if e != nil || len(operations) != 4 || strings.Join(actions, ",") != "probe-active-pair,read-accounting,nas-native,read-accounting" {
					t.Fatal("fixed genuine rejection graph unavailable", e, actions)
				}
			} else if e == nil {
				t.Fatal("incomplete rejection accepted", fault)
			}
			if fault == "before" && len(actions) > 2 {
				t.Fatal("native exchange ran into existing SQL state")
			}
		})
	}
}

// Pure typed observations exercise the sole strict decoder; they are not an
// installed node/process/readiness claim.
func negativeTestPair(p nasPrivatePlan) *sc.PairObservation {
	nodes := map[string]sc.NodeObservation{}
	for i, name := range []string{"green-primary", "green-secondary"} {
		n := sc.NodeObservation{Machine: "task11-" + name, Root: "/var/lib/cloud8021x-task11/roots/task11-" + name, MachineID: strings.Repeat(string(rune('1'+i)), 32), BootID: "11111111-2222-3333-4444-555555555555", Leader: 100 + i, LeaderStartTicks: 100, ApplicationSHA256: p.Scenario.ApplicationSHA256, ConfigSHA256: strings.Repeat("a", 64), Deployment: "task11-green", Epoch: p.Scenario.CollectionEpoch, WorkersActive: true, ReadyRoles: 2, Namespaces: map[string]uint64{}, Units: map[string]sc.UnitObservation{}, Collector: sc.CollectorObservation{BackingFile: "/var/lib/cloud-8021x-bootstrap/collector.ext4", FileDevice: 1, FileInode: uint64(10 + i), ByteSize: 512 << 20, Filesystem: "ext4", MountDevice: "/dev/loop1", MountActive: true, Options: []string{"nodev", "nosuid", "noexec"}}}
		for _, k := range []string{"pid", "mnt", "uts", "net", "cgroup"} {
			n.Namespaces[k] = uint64(10 + i)
		}
		for _, u := range []string{"cloud-8021x.service", "freeradius.service", "step-ca.service", "step-ca-rsa.service", "datadog-agent.service", "datadog-agent-ddot.service"} {
			n.Units[u] = sc.UnitObservation{Name: u, ActiveState: "active", MainPID: 200, ExecutableSHA256: strings.Repeat("a", 64), ControlGroup: "/system.slice/" + u, ProcessCgroup: "/system.slice/" + u, FragmentPath: "/etc/systemd/system/" + u}
		}
		nodes[name] = n
	}
	return &sc.PairObservation{Nodes: nodes}
}
