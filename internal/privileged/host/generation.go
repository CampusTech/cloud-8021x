package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"

	"github.com/CampusTech/cloud-8021x/internal/config"
)

type installedGeneration struct {
	Reference, ApplicationSHA256, ConfigSHA256 string
	TrustBindingVersion                        int    `json:"trust_binding_version,omitempty"`
	PostgresCASHA256                           string `json:"postgres_ca_sha256,omitempty"`
}

func installedHash(path string, maximum int64) (string, error) {
	f, err := rootFile(path, maximum)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	hash := sha256.New()
	if _, err = io.Copy(hash, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// KnownInstallation requires a prior completed Go installation and binds it to
// actual active bytes. A legacy binary/config pair alone is not that proof.
func KnownInstallation() (bool, error) {
	f, err := rootFile(transactionRoot+"/current.json", 4096)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	var generation installedGeneration
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&generation) != nil || decoder.Decode(new(any)) != io.EOF || (generation.TrustBindingVersion != 0 && generation.TrustBindingVersion != 1) || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(generation.Reference) {
		return false, errors.New("installed generation record rejected")
	}
	binary, err := installedHash("/usr/local/bin/cloud-8021x", 256<<20)
	if err != nil {
		return false, err
	}
	cfg, err := installedHash("/etc/cloud-8021x/config.yaml", 1<<20)
	if err != nil {
		return false, err
	}
	if binary != generation.ApplicationSHA256 || cfg != generation.ConfigSHA256 {
		return false, errors.New("active installation differs from completed generation")
	}
	if generation.TrustBindingVersion == 1 {
		ca, err := installedHash(PostgresCAFile, 1<<20)
		if err != nil || ca != generation.PostgresCASHA256 {
			return false, errors.New("active database trust differs from completed generation")
		}
	} else if generation.PostgresCASHA256 != "" {
		return false, errors.New("ambiguous historical database trust binding")
	}
	return true, nil
}
func (t *Transaction) CompleteInstalled() error {
	return t.completeInstalled(publishGeneration)
}
func (t *Transaction) completeInstalled(publish func(string) error) error {
	if t == nil || t.committed || t.receipt.Phase != "complete" {
		return errors.New("installation readiness is incomplete")
	}
	binary, err := installedHash("/usr/local/bin/cloud-8021x", 256<<20)
	if err != nil {
		return err
	}
	cfg, err := installedHash("/etc/cloud-8021x/config.yaml", 1<<20)
	if err != nil {
		return err
	}
	ca, err := installedHash(PostgresCAFile, 1<<20)
	if err != nil {
		return err
	}
	data, err := json.Marshal(installedGeneration{Reference: t.receipt.ID, ApplicationSHA256: binary, ConfigSHA256: cfg, TrustBindingVersion: 1, PostgresCASHA256: ca})
	if err != nil {
		return err
	}
	// Completion is a file in the same protected local rollback receipt as the
	// credential cache. Persist the exact prior bytes/owner/mode before publication:
	// rename can succeed even when its following directory sync reports failure.
	previous, err := Snapshot(File{Path: transactionRoot + "/current.json", Mode: 0600})
	if err != nil {
		return err
	}
	t.receipt.Files = append(t.receipt.Files, previous)
	if err = t.persist(t.receipt.Phase); err != nil {
		return err
	}
	temporary := filepath.Join(t.directory, "current.json")
	if err = privateWrite(temporary, data, 0600); err != nil {
		return err
	}
	if err = publish(temporary); err != nil {
		return err
	}
	t.committed = true
	return nil
}
func publishGeneration(temporary string) error {
	if err := os.Rename(temporary, transactionRoot+"/current.json"); err != nil {
		return err
	}
	directory, err := os.Open(transactionRoot)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}

func (t *Transaction) CaptureInitialState(ctx context.Context, current, previous Activation) error {
	active, err := current.Running(ctx)
	if err != nil {
		return err
	}
	if active && previous == nil {
		return errors.New("active legacy node must be explicitly quiesced before first Go activation")
	}
	t.receipt.WasRunning = active
	t.rollbackBackend = previous
	return t.persist(t.receipt.Phase)
}

// First adoption requires operator-fenced legacy application units/writers. This
// check independently rejects occupied replacement listener ports; it does not
// certify peer EAP success, writer fencing, import completion or zero disruption.
func CheckInitialListeners(c config.Config) error {
	addresses := []string{c.Listeners.Policy.Address, c.Listeners.HealthAddress, c.Listeners.MetricsAddress, net.JoinHostPort(c.Bootstrap.LocalAddress, "18122"), "0.0.0.0:8443", "0.0.0.0:8444"}
	if c.Listeners.Webhook.Enabled {
		addresses = append(addresses, c.Listeners.Webhook.Address)
	}
	if c.Listeners.Broker.Enabled {
		addresses = append(addresses, c.Listeners.Broker.Address)
	}
	listeners := []net.Listener{}
	defer func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}()
	seen := map[string]bool{}
	for _, address := range addresses {
		if address == "" || seen[address] {
			continue
		}
		seen[address] = true
		listener, err := net.Listen("tcp", address)
		if err != nil {
			return errors.New("initial application listener is occupied or not provably available")
		}
		listeners = append(listeners, listener)
	}
	return nil
}
