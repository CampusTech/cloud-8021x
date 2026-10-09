//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/migration"
)

func remoteSQL(ctx context.Context, e enrollment, project bool, node string) (sqlObservation, error) {
	action := "sql-observe"
	if project {
		action = "sql-project"
	}
	var observation sqlObservation
	raw, err := nodeCall(ctx, node, e, []string{action}, nil, sqlWireLimit, 30*time.Second)
	if err != nil {
		return observation, err
	}
	defer clear(raw)
	if observation, err = decodeSQLObservation(raw); err != nil {
		return observation, errors.New("actual private SQL observation invalid")
	}
	return observation, nil
}
func originalCertificateState(e enrollment) (migration.LegacyCertificateState, error) {
	var original migration.LegacyCertificateState
	raw, err := readPrivate(control+"/original-seed/source/var/lib/cloud-8021x/certificate-state.json", 16<<20, 0)
	if err != nil {
		return original, err
	}
	defer clear(raw)
	if !validSHA(e.Cloud.OriginalStateSHA256) || adoption.Digest(raw) != e.Cloud.OriginalStateSHA256 {
		return original, errors.New("approved original private state changed")
	}
	return migration.DecodeCertificates(raw)
}

func installedGreenHosts(e enrollment) (map[string]migration.LegacyCertificateHost, error) {
	raw, err := readPrivate(installedAPI+"/seed.json", 32<<20, 0)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	if adoption.Digest(raw) != e.Cloud.InstalledSeedSHA256 {
		return nil, errors.New("approved installed API seed changed")
	}
	return approvedGreenHosts(raw, e.ApplicationSHA256)
}

type displayBaseline struct {
	ApplicationSHA256 string
	Nodes             map[string]displayPin
}
type displayPin struct{ ConfigSHA256, DisplaySHA256 string }

func freezeDisplay(ctx context.Context, e enrollment) error {
	b := displayBaseline{ApplicationSHA256: e.ApplicationSHA256, Nodes: map[string]displayPin{}}
	for _, node := range []string{"green-primary", "green-secondary"} {
		o, err := remoteSQL(ctx, e, false, node)
		if err != nil {
			return err
		}
		if o.Enabled || o.Blocked {
			return errors.New("unactivated, unrevoked SQL epoch required before traffic")
		}
		for _, w := range o.Snapshot.Work {
			if w.Kind == "outbox" {
				return errors.New("freeze send-time display before first business work")
			}
		}
		b.Nodes[node] = displayPin{o.ConfigSHA256, o.DisplaySHA256}
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	// Exclusive baseline: a later observation cannot replace the display used
	// before actual sends. A changed cache makes verification fail, not adapt.
	if prior, readErr := readPrivate(control+"/display-before.json", 8192, 0); readErr == nil {
		if !bytes.Equal(prior, raw) {
			return errors.New("original display baseline changed")
		}
		return nil
	}
	return createPrivateOnce(control+"/display-before.json", raw)
}
func checkDisplay(e enrollment, node string, o sqlObservation) error {
	raw, err := readPrivate(control+"/display-before.json", 8192, 0)
	if err != nil {
		return err
	}
	var b displayBaseline
	if decodeExactJSON(raw, &b) != nil || b.ApplicationSHA256 != e.ApplicationSHA256 || len(b.Nodes) != 2 || b.Nodes[node] != (displayPin{o.ConfigSHA256, o.DisplaySHA256}) {
		return errors.New("send-time config/semantic display changed; historical enrichment cannot be reconstructed")
	}
	return nil
}
func installedCloudGate(ctx context.Context, e enrollment) error {
	if err := e.Cloud.validate(); err != nil {
		return err
	}
	green, err := installedGreenHosts(e)
	if err != nil {
		return err
	}
	original, err := originalCertificateState(e)
	if err != nil {
		return err
	}
	a, err := remoteSQL(ctx, e, true, "green-primary")
	if err != nil {
		return err
	}
	if err = checkDisplay(e, "green-primary", a); err != nil {
		return err
	}
	b, err := remoteSQL(ctx, e, true, "green-secondary")
	if err != nil {
		return err
	}
	if err = checkDisplay(e, "green-secondary", b); err != nil {
		return err
	}
	// Export workers may run on either physical peer. Different enrichment or
	// concurrent work snapshots are refused, never selected to match intake.
	if !reflect.DeepEqual(a.Records, b.Records) || !reflect.DeepEqual(a.Outbox, b.Outbox) {
		return errors.New("peer SQL/projection changed; freeze work and reconcile")
	}
	if !a.Blocked || a.Enabled || !b.Blocked || b.Enabled {
		return errors.New("installed reconciliation requires actual revoked epoch")
	}
	commands, err := projectCommands(a.Snapshot, original, green, "passive", true)
	if err != nil {
		return err
	}
	p := projection{Schema: 1, Gate: "installed-traffic", ApplicationSHA256: e.ApplicationSHA256, SeedSHA256: e.Cloud.InstalledSeedSHA256, DeploymentID: a.Snapshot.Deployment, Database: a.Snapshot.Database, CollectionEpoch: a.Snapshot.Epoch.UTC().Format(time.RFC3339), Records: a.Records, Outbox: a.Outbox, Commands: commands, Publications: map[string]string{}, Metrics: []metricExpectation{}}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	defer clear(raw)
	pin := adoption.Digest(raw)
	if err = atomicPrivate(installedAPI+"/expected.json", raw, 0); err != nil {
		return err
	}
	// This pin is computed before verifier invocation from actual SQL, independent
	// of intake. Preserve it as private evidence even when remote comparison fails.
	if err = recordEvidence(evidence{Stage: "sql-projection", Node: "green-primary+green-secondary", Operation: "expected", Status: "actual-read-only-snapshot", SHA256: pin, Bytes: len(raw)}); err != nil {
		return err
	}
	return verifyCloud(ctx, e, p, raw, pin)
}
func recoverCommands(ctx context.Context, e enrollment) error {
	green, err := installedGreenHosts(e)
	if err != nil {
		return err
	}
	original, err := originalCertificateState(e)
	if err != nil {
		return err
	}
	before, err := remoteSQL(ctx, e, false, "green-primary")
	if err != nil {
		return err
	}
	if before.Enabled || !before.Blocked {
		return errors.New("recovery requires genuine revoked SQL epoch")
	}
	commands, err := projectCommands(before.Snapshot, original, green, "passive", false)
	if err != nil {
		return err
	}
	for _, c := range commands {
		r := recoveryRequest{Kind: c.Origin, ApplicationSHA256: e.ApplicationSHA256}
		if c.Origin == "retained-legacy" {
			for _, g := range before.Snapshot.Guards {
				if g.Command.UUID == c.UUID {
					if r.Guard != "" && r.Guard != g.ID {
						return errors.New("multiple retained guard targets require independent reconciliation")
					}
					r.Guard = g.ID
				}
			}
		} else {
			for _, w := range before.Snapshot.Work {
				var p collectionPayload
				if strings.HasPrefix(w.Kind, "fleet-cert:") && decodeExactJSON(w.Payload, &p) == nil && p.UUID == c.UUID {
					r = workRecoveryRequest(w, e.ApplicationSHA256)
				}
			}
		}

		if c.Transport == "windows" {
			// Atomic remote snapshots supply only an untrusted locator. A missing or
			// stale snapshot refuses; it never authorizes a replay or changes expected SQL.
			hintState, readErr := readPrivate(installedAPI+"/remote-state.json", 32<<20, 0)
			if readErr != nil {
				return readErr
			}
			r.ExecutionID, err = remoteExecutionHint(hintState, e.Cloud.InstalledSeedSHA256, c)
			clear(hintState)
			if err != nil {
				return err
			}
		}
		if _, err = recoveryCommand(r); err != nil {
			return err
		}
		request, err := json.Marshal(r)
		if err != nil {
			return err
		}
		for _, scenario := range []string{"fleet-pending", "fleet-missing", "fleet-terminal"} {
			if err = cloudScenario(ctx, e, scenario, c.UUID, ""); err != nil {
				return err
			}
			raw, callErr := nodeCall(ctx, "green-primary", e, []string{"recover"}, request, 8192, 3*time.Minute)
			status := "expected-unresolved"
			if scenario == "fleet-terminal" {
				status = "terminal-command-exited-zero"
				if callErr != nil {
					return callErr
				}
			} else if callErr == nil {
				return errors.New("pending or missing remote command incorrectly resolved")
			}
			if err = recordEvidence(evidence{Stage: "recover", Node: "green-primary", Operation: scenario, Status: status, SHA256: adoption.Digest(raw), Bytes: len(raw)}); err != nil {
				return err
			}
		}
	}
	after, err := remoteSQL(ctx, e, false, "green-primary")
	if err != nil {
		return err
	}
	_, err = projectCommands(after.Snapshot, original, green, "passive", true)
	return err
}
