package main

import (
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"time"

	audit "github.com/CampusTech/cloud-8021x/tests/runtime/task11-passive-audit/contract"
)

type passivePins struct {
	ObserverSHA256, ObserverSourceSHA256, CloudSourceSHA256, ApplicationSourceSHA, OriginalSeedSHA256 string
	Manifests                                                                                         map[string]string
}
type passiveWindow struct {
	Schema           int    `json:"schema"`
	Kind             string `json:"kind"`
	Mode             string `json:"mode"`
	SeedSHA256       string `json:"seed_sha256"`
	Peer             string `json:"peer"`
	Role             string `json:"role"`
	Policy           string `json:"policy"`
	FromSequence     int    `json:"from_sequence"`
	ToSequence       int    `json:"to_sequence"`
	BaselineSHA256   string `json:"baseline_sha256"`
	EvidenceSHA256   string `json:"evidence_sha256"`
	Events           int    `json:"events"`
	ReadAttempts     int    `json:"read_attempts"`
	SuccessfulReads  int    `json:"successful_reads"`
	HTTPRequests     int    `json:"http_requests"`
	GRPCRequests     int    `json:"grpc_requests"`
	ControlEvents    int    `json:"control_events"`
	OtherPeerEvents  int    `json:"other_peer_events"`
	MutationAttempts int    `json:"mutation_attempts"`
}

func (p passivePins) validate() error {
	for key, pin := range p.Manifests {
		if key != "green-primary-prepared" && key != "green-secondary-prepared" && key != "green-primary-deactivated" && key != "green-secondary-deactivated" {
			return errors.New("unknown phase manifest pin")
		}
		if !validSHA(pin) {
			return errors.New("invalid phase manifest pin")
		}
	}
	for _, v := range []string{p.ObserverSHA256, p.ObserverSourceSHA256, p.CloudSourceSHA256, p.OriginalSeedSHA256} {
		if !validSHA(v) {
			return errors.New("reviewed passive source/binary/seed pins required")
		}
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(p.ApplicationSourceSHA) {
		return errors.New("clean shipping source revision required")
	}
	return nil
}
func greenPeer(node string) (string, error) {
	switch node {
	case "green-primary":
		return "10.203.11.21", nil
	case "green-secondary":
		return "10.203.11.22", nil
	}
	return "", errors.New("fixed green physical node required")
}
func validatePassiveWindow(raw []byte, seed, node string, baseline *passiveWindow) (passiveWindow, error) {
	var v passiveWindow
	var fields map[string]json.RawMessage
	if len(raw) > 8192 || decodeExactJSON(raw, &fields) != nil || decodeExactJSON(raw, &v) != nil {
		return v, errors.New("invalid passive API window output")
	}
	typ := reflect.TypeFor[passiveWindow]()
	if len(fields) != typ.NumField() {
		return v, errors.New("incomplete passive API window")
	}
	for i := 0; i < typ.NumField(); i++ {
		if _, ok := fields[typ.Field(i).Tag.Get("json")]; !ok {
			return v, errors.New("missing passive API window field")
		}
	}
	peer, err := greenPeer(node)
	if err != nil {
		return v, err
	}
	if v.Schema != 1 || v.Kind != "passive-peer-audit" || v.SeedSHA256 != seed || !validSHA(seed) || v.Peer != peer || v.Role != node || v.Policy != "passive" || !validSHA(v.BaselineSHA256) || !validSHA(v.EvidenceSHA256) || v.MutationAttempts != 0 {
		return v, errors.New("passive API window binding differs")
	}
	for _, n := range []int{v.FromSequence, v.ToSequence, v.Events, v.ReadAttempts, v.SuccessfulReads, v.HTTPRequests, v.GRPCRequests, v.ControlEvents, v.OtherPeerEvents} {
		if n < 0 || n > 1000000 {
			return v, errors.New("passive API window count invalid")
		}
	}
	if v.ToSequence < v.FromSequence || v.Events+v.ControlEvents+v.OtherPeerEvents != v.ToSequence-v.FromSequence || v.HTTPRequests+v.GRPCRequests != v.Events || v.ReadAttempts != v.Events || v.SuccessfulReads > v.ReadAttempts {
		return v, errors.New("passive API window counts differ")
	}
	if baseline == nil {
		if v.Mode != "baseline" || v.FromSequence != v.ToSequence {
			return v, errors.New("actual baseline required")
		}
	} else if v.Mode != "final" || v.FromSequence != baseline.ToSequence || v.BaselineSHA256 != baseline.BaselineSHA256 || baseline.SeedSHA256 != seed || baseline.Role != node || baseline.Mode != "baseline" {
		return v, errors.New("final API window differs from retained baseline")
	}
	return v, nil
}
func stableFiles(a, b map[string]audit.File) bool {
	if len(a) != len(b) {
		return false
	}
	for k, x := range a {
		y, ok := b[k]
		if !ok {
			return false
		}
		x.Device = 0
		x.Inode = 0
		y.Device = 0
		y.Inode = 0
		if x != y {
			return false
		}
	}
	return true
}
func comparePassiveBoot(before, after audit.Result) error {
	if before.Identity.BootID == after.Identity.BootID || before.Identity.MachineID != after.Identity.MachineID || before.Identity.Hostname != after.Identity.Hostname || before.Identity.PID1 != after.Identity.PID1 || before.Identity.PID1Executable != after.Identity.PID1Executable {
		return errors.New("genuine enrolled reboot identity not preserved")
	}
	a, b := before, after
	a.RequestSHA256 = ""
	b.RequestSHA256 = ""
	a.ObservedAt = time.Time{}
	b.ObservedAt = time.Time{}
	a.Identity = audit.Identity{}
	b.Identity = audit.Identity{}
	a.Processes = nil
	b.Processes = nil
	a.Sockets = nil
	b.Sockets = nil
	a.Units = nil
	b.Units = nil
	if !stableFiles(a.Preserved, b.Preserved) || !stableFiles(a.State, b.State) {
		return errors.New("preserved content changed across reboot")
	}
	a.Preserved = nil
	b.Preserved = nil
	a.State = nil
	b.State = nil
	// Device numbers may change across reboot, but the
	// persistent backing inode, image size and filesystem UUID must not.
	a.Collector.Device = ""
	b.Collector.Device = ""
	a.Collector.Source = ""
	b.Collector.Source = ""
	a.Collector.Image.Device = 0
	b.Collector.Image.Device = 0

	if !reflect.DeepEqual(a, b) {
		return errors.New("passive SQL, enrollment or persistent filesystem changed across reboot")
	}
	return nil
}
