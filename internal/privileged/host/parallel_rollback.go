package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/config"
)

func destinationPin(c config.Config, role string) (ed25519.PublicKey, error) {
	pin := c.Deployment.DestinationPrimaryKey
	if role == "radius-secondary" {
		pin = c.Deployment.DestinationSecondaryKey
	}
	key, err := hex.DecodeString(pin)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("reviewed destination receipt key required")
	}
	return ed25519.PublicKey(key), nil
}

// WriteParallelRollback publishes only the proof whose database and local
// physical fences the protected caller has just verified. No data is restored.
func WriteParallelRollback(c config.Config, release, fence string) (string, error) {
	name, err := os.Hostname()
	if err != nil || strings.Split(name, ".")[0] != c.Deployment.Instance {
		return "", errors.New("rollback proof must originate on the exact green instance")
	}
	pin, err := destinationPin(c, c.InstanceID)
	if err != nil {
		return "", err
	}
	key, err := readPrivateCache(parallelSourceKey, ed25519.PrivateKeySize)
	if err != nil || len(key) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.PrivateKey(key).Public().(ed25519.PublicKey), pin) {
		return "", errors.New("green receipt signing key differs from reviewed pin")
	}
	manifest, err := c.ParallelManifest()
	if err != nil {
		return "", err
	}
	raw, err := adoption.SignRollback(adoption.Rollback{ManifestSHA256: manifest, ReleaseSHA256: release, Transition: c.StateTransition, Deployment: c.Deployment.ID, SourceDeployment: c.Deployment.SourceID, Role: c.InstanceID, Instance: c.Deployment.Instance, FenceSHA256: fence, ObservedAt: time.Now().UTC(), CommandsReconciled: true}, ed25519.PrivateKey(key))
	if err != nil {
		return "", err
	}
	path := transactionRoot + "/rollback-" + c.InstanceID + ".json"
	return path, Write(File{Path: path, Data: raw, Mode: 0600})
}

// ResumeParallelSource accepts only two fresh pinned green proofs and the
// existing original local fence lineage. It restores scheduler files only;
// neither accounting nor CA state is transferred backwards.
func ResumeParallelSource(ctx context.Context, c config.Config, release string) error {
	return resumeParallelSource(ctx, c, release, execute)
}
func resumeParallelSource(ctx context.Context, c config.Config, release string, run commandRunner) error {
	source := c.Deployment.SourcePrimary
	if c.InstanceID == "radius-secondary" {
		source = c.Deployment.SourceSecondary
	}
	name, err := os.Hostname()
	if err != nil || strings.Split(name, ".")[0] != source {
		return errors.New("resume must run on the original physical source")
	}
	manifest, err := c.ParallelManifest()
	if err != nil {
		return err
	}
	for _, role := range []string{"radius-primary", "radius-secondary"} {
		key, err := destinationPin(c, role)
		if err != nil {
			return err
		}
		raw, err := readPrivateCache(ArtifactDirectory+"/rollback-"+role+".json", 64<<10)
		if err != nil {
			return err
		}
		if _, err = adoption.VerifyRollback(raw, key, manifest, release, c.StateTransition, c.Deployment.ID, c.Deployment.SourceID, role, time.Now()); err != nil {
			return err
		}
	}
	unlock, err := AcquireWriterOperation()
	if err != nil {
		return err
	}
	defer unlock()
	binding, err := adoption.ExpectedBinding(c, strings.Repeat("0", 64))
	if err != nil {
		return err
	}
	if _, err = fenceLegacyWriters(ctx, c.StateTransition, c.InstanceID, binding.ConfigSHA256, run, legacyProcessesQuiescent); err != nil {
		return err
	}
	return restoreLegacyWriterFiles(c.StateTransition, run)
}

func VerifyParallelDestinationKey(c config.Config) error {
	if err := CheckParallelDestination(c); err != nil {
		return err
	}
	if err := c.ValidateHandoffPins(); err != nil {
		return err
	}
	pin, err := destinationPin(c, c.InstanceID)
	if err != nil {
		return err
	}
	key, err := readPrivateCache(parallelSourceKey, ed25519.PrivateKeySize)
	if err != nil || len(key) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.PrivateKey(key).Public().(ed25519.PublicKey), pin) {
		return errors.New("physical green receipt key differs from reviewed deployment pin")
	}
	return nil
}
