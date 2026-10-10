package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
)

const parallelPrepareFile = transactionRoot + "/parallel-prepare.json"

type parallelPrepareHelper struct {
	ConfigSHA256, ReleaseSHA256 string
	Helper                      writerPID
}

func BeginParallelPrepare(c config.Config, release string) error {
	binding, err := adoption.ExpectedBinding(c, release)
	if err != nil {
		return err
	}
	processes, err := scanWriterProcesses()
	if err != nil {
		return err
	}
	proof := parallelPrepareHelper{ConfigSHA256: binding.ConfigSHA256, ReleaseSHA256: release}
	for _, p := range processes {
		if p.PID == os.Getpid() {
			proof.Helper = writerPID{p.PID, p.Start}
		}
	}
	if proof.Helper.Start == 0 {
		return errors.New("preparation helper process identity unavailable")
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	if err = protectedDirectory(transactionRoot, 0, 0, 0700); err != nil {
		return err
	}
	return Write(File{Path: parallelPrepareFile, Data: raw, Mode: 0600})
}

// ParallelInstalledReceipt reuses the completed physical generation, never a new
// random transaction reference, when preparation is retried after success.
func ParallelInstalledReceipt(c config.Config, release string) (string, string, error) {
	known, err := KnownInstallation()
	if err != nil || !known {
		return "", "", err
	}
	raw, err := readPrivateCache(transactionRoot+"/current.json", 4096)
	if err != nil {
		return "", "", err
	}
	var generation installedGeneration
	if domain.DecodeJSONStrict(raw, &generation) != nil || generation.ApplicationSHA256 != release {
		return "", "", errors.New("completed parallel release differs")
	}
	installed, err := config.Load("/etc/cloud-8021x/config.yaml")
	if err != nil {
		return "", "", err
	}
	a, _ := json.Marshal(c)
	b, _ := json.Marshal(installed)
	if string(a) != string(b) {
		return "", "", errors.New("completed parallel configuration differs")
	}
	trust, err := ReadClientTrust()
	if err != nil {
		return "", "", err
	}
	return generation.Reference, digestBytes(trust), nil
}

// RecoverParallelPrepare is the closed passive preparation recovery callback.
// The shared attempt supplies its original installation reference; the caller
// holds the root writer lock. No arbitrary path, phase, or payload is accepted.
func RecoverParallelPrepare(ctx context.Context, c config.Config, release, reference string) (string, string, error) {
	return recoverParallelPrepare(ctx, c, release, reference, execute)
}
func recoverParallelPrepare(ctx context.Context, c config.Config, release, reference string, run commandRunner) (string, string, error) {
	raw, err := readPrivateCache(parallelPrepareFile, 4096)
	if errors.Is(err, os.ErrNotExist) && reference == "" {
		return "", "", installParallelPassiveBarrier(ctx, run)
	}
	if err != nil {
		return "", "", err
	}
	var proof parallelPrepareHelper
	binding, err := adoption.ExpectedBinding(c, release)
	if err != nil {
		return "", "", err
	}
	if domain.DecodeJSONStrict(raw, &proof) != nil || proof.ConfigSHA256 != binding.ConfigSHA256 || proof.ReleaseSHA256 != release || proof.Helper.PID <= 0 || proof.Helper.Start == 0 {
		return "", "", errors.New("original preparation helper identity differs")
	}
	processes, err := scanWriterProcesses()
	if err != nil {
		return "", "", err
	}
	for _, p := range processes {
		if p.PID == proof.Helper.PID && p.Start == proof.Helper.Start {
			return "", "", errors.New("original preparation helper remains alive")
		}
	}
	if err = installParallelPassiveBarrier(ctx, run); err != nil {
		return "", "", err
	}
	receipt, trust, err := ParallelInstalledReceipt(c, release)
	if err != nil {
		return "", "", err
	}
	if receipt != "" {
		if receipt != reference {
			return "", "", errors.New("shared and physical installation receipts differ")
		}
		return receipt, trust, nil
	}
	if reference == "" {
		return "", "", nil
	}
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(reference) {
		return "", "", errors.New("invalid original installation reference")
	}
	directory := filepath.Join(transactionRoot, reference)
	raw, err = readPrivateCache(filepath.Join(directory, "receipt.json"), 32<<20)
	if err != nil {
		return "", "", err
	}
	var saved Receipt
	if domain.DecodeJSONStrict(raw, &saved) != nil || saved.ID != reference || saved.WasRunning {
		return "", "", errors.New("original passive installation receipt rejected")
	}
	transaction := &Transaction{receipt: saved, directory: directory}
	backend := &RadiusBackend{Companions: true}
	if err = transaction.Rollback(ctx, &PassiveRadius{Backend: backend}, false); err != nil {
		return "", "", err
	}
	if transaction.receipt.PackageBarrier {
		if err = transaction.UnmaskPackages(ctx, backend); err != nil {
			return "", "", err
		}
	}
	return "", "", nil
}

func PublishParallelAuthorization(ctx context.Context, c config.Config, doc adoption.Authorization, a Accounts) error {
	if err := parallelUnitsStopped(ctx, execute); err != nil {
		return err
	}
	data, err := validateAdoptionSnapshot(doc.Policy, c.Policy.IdentityMode, doc.FingerprintEnforced)
	if err != nil {
		return err
	}
	if doc.FingerprintEnforced {
		if err = Write(File{Path: legacyDowngradeGuard, Data: []byte("fingerprint\n"), Mode: 0644}); err != nil {
			return err
		}
	}
	return Write(File{Path: daemonPolicySnapshot, Data: data, UID: a.RuntimeUID, GID: a.RuntimeGID, Mode: 0644})
}

const parallelActivationHelperFile = transactionRoot + "/parallel-activation-helper.json"

func BeginParallelActivation(c config.Config, release string) error {
	binding, err := adoption.ExpectedBinding(c, release)
	if err != nil {
		return err
	}
	proof := parallelPrepareHelper{ConfigSHA256: binding.ConfigSHA256, ReleaseSHA256: release}
	processes, err := scanWriterProcesses()
	if err != nil {
		return err
	}
	for _, p := range processes {
		if p.PID == os.Getpid() {
			proof.Helper = writerPID{p.PID, p.Start}
		}
	}
	if proof.Helper.Start == 0 {
		return errors.New("activation helper identity unavailable")
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	return Write(File{Path: parallelActivationHelperFile, Data: raw, Mode: 0600})
}
func VerifyParallelActivationRecovery(ctx context.Context, c config.Config, release string) error {
	raw, err := readPrivateCache(parallelActivationHelperFile, 4096)
	if errors.Is(err, os.ErrNotExist) {
		return parallelUnitsStopped(ctx, execute)
	}
	if err != nil {
		return err
	}
	binding, err := adoption.ExpectedBinding(c, release)
	if err != nil {
		return err
	}
	var proof parallelPrepareHelper
	if domain.DecodeJSONStrict(raw, &proof) != nil || proof.ConfigSHA256 != binding.ConfigSHA256 || proof.ReleaseSHA256 != release || proof.Helper.PID <= 0 || proof.Helper.Start == 0 {
		return errors.New("original activation helper differs")
	}
	processes, err := scanWriterProcesses()
	if err != nil {
		return err
	}
	for _, p := range processes {
		if p.PID == proof.Helper.PID && p.Start == proof.Helper.Start {
			return errors.New("original activation helper remains alive")
		}
	}
	return nil
}
