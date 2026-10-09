package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/config"
)

const ParallelPublicActivationFile = "/etc/cloud-8021x/parallel-activation.json"

type ParallelActivation struct{ Deployment, Instance, Transition, ConfigSHA256 string }

func ParallelActivationBinding(c config.Config) ParallelActivation {
	raw, _ := json.Marshal(c)
	return ParallelActivation{c.Deployment.ID, c.Deployment.Instance, c.StateTransition, digestBytes(raw)}
}
func PublishParallelActivation(c config.Config) error {
	if os.Geteuid() != 0 || !c.Parallel() {
		return errors.New("root parallel activation required")
	}
	if known, err := KnownInstallation(); err != nil || !known {
		return errors.New("complete protected parallel installation required")
	}
	raw, err := json.Marshal(ParallelActivationBinding(c))
	if err != nil {
		return err
	}
	// Public evidence is readable by the daemon but only root can create it.
	if err = Write(File{Path: ParallelPublicActivationFile, Data: raw, Mode: 0644}); err != nil {
		return err
	}
	return Write(File{Path: ParallelActiveFile, Data: raw, Mode: 0600})
}
func StopParallel(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("root parallel fencing required")
	}
	for _, path := range []string{ParallelActiveFile, ParallelPublicActivationFile} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := syncWriterDirectory(transactionRoot); err != nil {
		return err
	}
	for _, unit := range []string{"cloud-8021x-sources.timer", "cloud-8021x-renew.timer", "cloud-8021x-sources.service", "cloud-8021x-renew.service", "freeradius.service", "step-ca.service", "step-ca-rsa.service", "cloud-8021x.service", "datadog-agent-ddot.service", "datadog-agent.service"} {
		if _, err := execute(ctx, "/usr/bin/systemctl", "stop", unit); err != nil {
			return err
		}
	}
	if err := parallelUnitsStopped(ctx, execute); err != nil {
		return err
	}
	return nativeListenersQuiescent()
}

func StartParallelRenewTimer(ctx context.Context) error {
	_, err := execute(ctx, "/usr/bin/systemctl", "enable", "--now", "cloud-8021x-renew.timer")
	return err
}

func CheckParallelDestination(c config.Config) error {
	name, err := os.Hostname()
	if err != nil || !c.Parallel() || strings.Split(name, ".")[0] != c.Deployment.Instance {
		return errors.New("operation requires the exact physical green destination")
	}
	return c.ValidateDeployment()
}
