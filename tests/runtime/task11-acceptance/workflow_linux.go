//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	audit "github.com/CampusTech/cloud-8021x/tests/runtime/task11-passive-audit/contract"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type evidence struct {
	Stage, Node, Operation, Status, SHA256 string
	Bytes                                  int
	At                                     time.Time
}

func recordEvidence(v evidence) error {
	// Private, exclusive records survive a later failure. No envelopes, command
	// output, credentials or TLS identities are serialized into evidence.
	entries, err := os.ReadDir(control)
	if err != nil {
		return err
	}
	count := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "evidence-") {
			count++
		}
	}
	if count >= 4096 {
		return errors.New("acceptance evidence bound reached; archive before further stages")
	}
	v.At = time.Now().UTC()
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	name := fmt.Sprintf("%s/evidence-%d.json", control, time.Now().UnixNano())
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	return err
}
func publicResult(raw []byte, key string) (string, error) {
	var fields map[string]string
	if domain.DecodeJSONStrict(raw, &fields) != nil || !hex64.MatchString(fields[key]) {
		return "", errors.New("invalid public shipping result")
	}
	return fields[key], nil
}
func remoteConfig(ctx context.Context, n string, e enrollment) (config.Config, error) {
	var c config.Config
	raw, err := nodeCall(ctx, n, e, []string{"config"}, nil, 2<<20, 15*time.Second)
	if err != nil {
		return c, err
	}
	if domain.DecodeJSONStrict(raw, &c) != nil {
		return c, errors.New("invalid typed node configuration")
	}
	return c, c.ValidateHandoffPins()
}
func checkPair(ctx context.Context, e enrollment) error {
	seenNS := map[string]map[string]bool{}
	for _, name := range nsNames {
		seenNS[name] = map[string]bool{}
	}
	manifest := ""
	roles := map[string]string{}
	for _, n := range nodes {
		m, err := inspectMachine(ctx, n, e)
		if err != nil {
			return err
		}
		for _, name := range nsNames {
			value := m.Proof.Namespaces[name]
			if seenNS[name][value] {
				return errors.New("nodes share a required private namespace")
			}
			seenNS[name][value] = true
		}
		c, err := remoteConfig(ctx, n, e)
		if err != nil {
			return err
		}
		if c.Deployment.ID != "task11-green" || c.Deployment.SourceID != "task11-blue" || c.Deployment.SourcePrimary != "task11-blue-primary" || c.Deployment.SourceSecondary != "task11-blue-secondary" || c.InstanceID != roleOf(n) {
			return errors.New("synthetic physical deployment binding differs")
		}
		d := c.Deployment
		if d.SourcePrimaryKey != e.Nodes["blue-primary"].Pin || d.SourceSecondaryKey != e.Nodes["blue-secondary"].Pin || d.DestinationPrimaryKey != e.Nodes["green-primary"].Pin || d.DestinationSecondaryKey != e.Nodes["green-secondary"].Pin {
			return errors.New("node pin configuration differs from owned enrollment")
		}
		b, err := adoption.ExpectedBinding(c, e.ApplicationSHA256)
		if err != nil {
			return err
		}
		if manifest != "" && manifest != b.ManifestSHA256 {
			return errors.New("pair manifest differs")
		}
		manifest = b.ManifestSHA256
		if prior := roles[c.InstanceID]; prior != "" && prior != b.ConfigSHA256 {
			return errors.New("source and destination role configurations differ")
		}
		roles[c.InstanceID] = b.ConfigSHA256
	}
	return nil
}
func checkPin(ctx context.Context, n string, e enrollment) error {
	raw, err := nodeCall(ctx, n, e, []string{"op", "source-key", e.ApplicationSHA256}, nil, 8192, 20*time.Minute)
	if err != nil {
		return err
	}
	pin, err := publicResult(raw, "source_public_key")
	if err != nil {
		return err
	}
	if pin != e.Nodes[n].Pin {
		return errors.New("real source-key result differs from enrolled physical pin")
	}
	return nil
}
func transfer(ctx context.Context, from, to, kind string, e enrollment) error {
	role := roleOf(from)
	raw, err := nodeCall(ctx, from, e, []string{"receipt-digest", kind, role}, nil, 8192, 15*time.Second)
	if err != nil {
		return err
	}
	digest, err := publicResult(raw, "sha256")
	if err != nil {
		return err
	}
	payload, err := nodeCall(ctx, from, e, []string{"read", kind, role, digest}, nil, adoption.MaxBytes, 30*time.Second)
	if err != nil {
		return err
	}
	defer clear(payload)
	if adoption.Digest(payload) != digest {
		return errors.New("source private pipe digest differs")
	}
	c, err := remoteConfig(ctx, to, e)
	if err != nil {
		return err
	}
	if err = verifyReceipt(kind, role, payload, c, e.ApplicationSHA256, time.Now().UTC()); err != nil {
		return err
	}
	ack, err := nodeCall(ctx, to, e, []string{"write", kind, role, digest}, payload, 8192, 30*time.Second)
	if err != nil {
		return err
	}
	got, err := publicResult(ack, "sha256")
	if err != nil || got != digest {
		return errors.New("destination acknowledgement differs")
	}
	return recordEvidence(evidence{Stage: "transfer", Node: from + "->" + to, Operation: kind, Status: "verified-private-copy", SHA256: digest, Bytes: len(payload)})
}
func collectAndFreezePins(ctx context.Context, e *enrollment) error {
	pins := map[string]string{}
	seen := map[string]bool{}
	for _, n := range nodes {
		raw, err := nodeCall(ctx, n, *e, []string{"op", "source-key", e.ApplicationSHA256}, nil, 8192, 20*time.Minute)
		if err != nil {
			return err
		}
		pin, err := publicResult(raw, "source_public_key")
		if err != nil {
			return err
		}
		if seen[pin] || (e.Nodes[n].Pin != "" && e.Nodes[n].Pin != pin) {
			return errors.New("receipt keys are shared or changed")
		}
		seen[pin] = true
		pins[n] = pin
	}
	payload, err := json.Marshal(pins)
	if err != nil {
		return err
	}
	for _, n := range nodes {
		m, err := inspectMachine(ctx, n, *e)
		if err != nil {
			return err
		}
		raw, err := namespaceCall(ctx, m, []string{"pin-config"}, payload, 8192, 15*time.Second)
		if err != nil {
			return err
		}
		digest, err := publicResult(raw, "config_sha256")
		if err != nil {
			return err
		}
		updated := e.Nodes[n]
		updated.Pin = pins[n]
		updated.ConfigSHA256 = digest
		e.Nodes[n] = updated
		after, err := inspectMachine(ctx, n, *e)
		if err != nil || after.Leader != m.Leader || after.Start != m.Start || after.Proof.BootID != m.Proof.BootID {
			return errors.New("node changed while freezing pins; review partial configuration")
		}
		state, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if err = atomicPrivate(control+"/enrollment.json", state, 0); err != nil {
			return err
		}
		if err = recordEvidence(evidence{Stage: "keys", Node: n, Operation: "pin-config", Status: "frozen", SHA256: digest}); err != nil {
			return err
		}
	}
	return checkPair(ctx, *e)
}
func executeStage(ctx context.Context, stage string, logger *logrus.Logger) error {
	if err := fixtureGuard(); err != nil {
		return err
	}
	e, err := loadEnrollment()
	if err != nil {
		return err
	}
	self, err := fileDigest(helper, 256<<20)
	if err != nil || self != e.ControllerSHA256 {
		return errors.New("outer controller digest differs")
	}
	// Refuse two controllers even if their individual node operations differ.
	parent, err := privateParent(control+"/controller.lock", 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	fd, err := unix.Openat(parent, "controller.lock", unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	if err = fileStat(fd, 0, 0); err != nil {
		return err
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.New("another guest controller is active")
	}
	if stage == "keys" {
		return collectAndFreezePins(ctx, &e)
	}
	if err = checkPair(ctx, e); err != nil {
		return err
	}

	switch stage {
	case "observe":
		return freezeDisplay(ctx, e)
	case "recover":
		return recoverCommands(ctx, e)
	case "verify-cloud":
		return installedCloudGate(ctx, e)
	case "cutover":
		if err = primitiveCloudGate(ctx, e); err != nil {
			return err
		}
		// Actual pinned observer + genuine reboot + retained API window are
		// independent of the cloud primitive and must all pass before final capture.
		if err = installedPassiveAudit(ctx, e); err != nil {
			return err
		}
	}

	var window *retainedPassiveWindow
	if stage == "prepare" || stage == "cutover" || stage == "proofs" || stage == "resume" {
		if err = e.Passive.validate(); err != nil {
			return err
		}
		w, er := startPassiveWindow(ctx, e, stage)
		if er != nil {
			return er
		}
		window = &w
		if stage == "proofs" || stage == "resume" {
			if err = passivePair(ctx, e, "deactivated", false); err != nil {
				return err
			}
		}
	}
	plan, err := stagePlan(stage)
	if err != nil {
		return err
	}
	activationCount := 0
	for _, s := range plan {
		logger.WithFields(logrus.Fields{"stage": stage, "node": s.Node, "operation": s.Operation}).Info("running owned acceptance step")
		if err = checkPin(ctx, s.Node, e); err != nil {
			return err
		}
		switch s.Operation {
		case "transfer":
			err = transfer(ctx, s.Node, strings.Replace(s.Node, "blue-", "green-", 1), "parallel", e)
		case "reverse-transfer":
			for _, target := range []string{"blue-primary", "blue-secondary"} {
				if err = transfer(ctx, s.Node, target, "rollback", e); err != nil {
					break
				}
			}

		default:
			var prepared audit.Manifest
			if s.Operation == "prepare" {
				prepared, err = expectedPreparedManifest(ctx, e, s.Node)
				if err != nil {
					return err
				}
			}
			if s.Operation == "activate" && activationCount == 0 {
				if err = freezeDisplay(ctx, e); err != nil {
					return err
				}
				if err = passivePair(ctx, e, "prepared", false); err != nil {
					return err
				}
				if window == nil {
					return errors.New("actual before-capture API baseline absent")
				}
				if err = finishPassiveWindow(ctx, e, *window); err != nil {
					return err
				}
				window = nil
			}
			var raw []byte
			raw, err = nodeCall(ctx, s.Node, e, []string{"op", s.Operation, e.ApplicationSHA256}, nil, 1<<20, 20*time.Minute)
			status := "command-exited-zero"
			if err == nil && s.Operation == "prepare" {
				err = savePassiveManifest(ctx, &e, s.Node, "prepared", prepared)
			}
			if err != nil {
				status = "command-failed-reconcile-state"
			}
			if err == nil && s.Operation == "activate" {
				var active bool
				active, err = validateActivation(raw, s.Node)
				activationCount++
				if err == nil && ((activationCount == 1 && active) || (activationCount > 1 && !active)) {
					err = errors.New("unexpected shipping activation phase")
				}
				if err == nil && activationCount == 1 {
					err = cloudScenario(ctx, e, "fleet-uncertain", "", "")
					if err == nil {
						err = cloudScenario(ctx, e, "intake-unavailable", "", "")
					}
					for _, peer := range []string{"10.203.11.21", "10.203.11.22"} {
						if err == nil {
							err = cloudScenario(ctx, e, "peer-active", "", peer)
						}
					}
					if err == nil {
						err = recordEvidence(evidence{Stage: "cutover", Node: "green-pair", Operation: "permission-ready", Status: "api-permitted-product-still-pending"})
					}
				}
			}
			if err == nil && s.Operation == "deactivate" {
				cfg, configErr := remoteConfig(ctx, s.Node, e)
				if configErr != nil {
					err = configErr
				} else {
					err = validateDeactivation(raw, roleOf(s.Node), cfg.StateTransition)
				}
				if err == nil {
					peer := "10.203.11.21"
					if s.Node == "green-secondary" {
						peer = "10.203.11.22"
					}
					err = cloudScenario(ctx, e, "peer-passive", "", peer)
				}
			}
			if err != nil {
				status = "command-or-followup-failed-reconcile-state"
			}
			recordErr := recordEvidence(evidence{Stage: stage, Node: s.Node, Operation: s.Operation, Status: status, SHA256: adoption.Digest(raw), Bytes: len(raw)})
			clear(raw)
			if err == nil {
				err = recordErr
			}
		}
		if err != nil {
			return err
		}
	}

	if stage == "prepare" {
		if err = passivePair(ctx, e, "prepared", true); err != nil {
			return err
		}
	}
	if stage == "deactivate" {
		w, er := startPassiveWindow(ctx, e, "deactivated-reboot")
		if er != nil {
			return er
		}
		window = &w
		if err = freezeDeactivatedManifests(ctx, &e); err != nil {
			return err
		}
		if err = passivePair(ctx, e, "deactivated", true); err != nil {
			return err
		}
	}
	if stage == "proofs" || stage == "resume" {
		if err = passivePair(ctx, e, "deactivated", false); err != nil {
			return err
		}
	}
	if window != nil {
		if err = finishPassiveWindow(ctx, e, *window); err != nil {
			return err
		}
	}
	if stage == "cutover" {
		if activationCount != 3 {
			return errors.New("complete actual activation pair required")
		}
		for _, node := range []string{"green-primary", "green-secondary"} {
			raw, err := nodeCall(ctx, node, e, []string{"active-proof"}, nil, 32<<20, 30*time.Second)
			if err != nil {
				return err
			}
			var o sqlObservation
			if decodeExactJSON(raw, &o) != nil || !o.Enabled || o.Blocked || o.Ready != 2 {
				return errors.New("actual SQL/PID1 activation not established")
			}
		}
		if err = recordEvidence(evidence{Stage: "cutover", Node: "green-pair", Operation: "actual-activation", Status: "shipping-cli-sql-pid1-active"}); err != nil {
			return err
		}
		if err = cloudScenario(ctx, e, "intake-ready", "", ""); err != nil {
			return err
		}
	}
	// Exiting zero means only the requested CLI steps returned zero. Independent
	// Packet acceptance and final independent cloud reconciliation remain separate gates.
	return nil
}

func requestedStage(ctx context.Context) error {
	if err := fixtureGuard(); err != nil {
		return err
	}
	raw, err := readPrivate(control+"/stage.json", 1024, 0)
	if err != nil {
		return err
	}
	var request struct {
		Stage string `json:"stage"`
	}
	if domain.DecodeJSONStrict(raw, &request) != nil {
		return errors.New("invalid fixed stage request")
	}
	if _, err = stagePlan(request.Stage); err != nil {
		return err
	}
	return executeStage(ctx, request.Stage, logrus.New())
}
