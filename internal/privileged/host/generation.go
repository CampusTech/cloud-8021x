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

type installedGeneration struct{ Reference, ApplicationSHA256, ConfigSHA256 string }

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
	if decoder.Decode(&generation) != nil || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(generation.Reference) {
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
	return true, nil
}
func (t *Transaction) CompleteInstalled() error {
	if t == nil || t.receipt.Phase != "complete" {
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
	data, err := json.Marshal(installedGeneration{t.receipt.ID, binary, cfg})
	if err != nil {
		return err
	}
	temporary := filepath.Join(t.directory, "current.json")
	if err = privateWrite(temporary, data, 0600); err != nil {
		return err
	}
	if err = os.Rename(temporary, transactionRoot+"/current.json"); err != nil {
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
