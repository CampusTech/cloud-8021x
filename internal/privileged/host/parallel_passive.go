package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const ParallelActiveFile = transactionRoot + "/parallel-active.json"

// ParallelPassiveFiles must be durably installed before any package operation.
// They survive reboot and apply to package-owned units as well as daemon units.
func ParallelPassiveFiles() []File {
	var files []File
	for _, unit := range []string{"cloud-8021x.service", "freeradius.service", "step-ca.service", "step-ca-rsa.service", "cloud-8021x-renew.service", "cloud-8021x-sources.service", "datadog-agent.service", "datadog-agent-ddot.service"} {
		files = append(files, File{Path: "/etc/systemd/system/" + unit + ".d/parallel.conf", Data: []byte("[Unit]\nConditionPathExists=" + ParallelActiveFile + "\n"), Mode: 0644})
	}
	return files
}

// InstallParallelPassiveBarrier refuses a live/previously activated node. It is
// intentionally retained on failed preparation: an interrupted install cannot
// become active merely because /run masks disappear after reboot.
func InstallParallelPassiveBarrier(ctx context.Context) error {
	return installParallelPassiveBarrier(ctx, execute)
}
func installParallelPassiveBarrier(ctx context.Context, run commandRunner) error {
	if os.Geteuid() != 0 {
		return errors.New("root passive preparation required")
	}
	if f, err := rootFile(ParallelActiveFile, 64<<10); err == nil {
		_ = f.Close()
		return errors.New("parallel deployment already activated")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := parallelUnitsStopped(ctx, run); err != nil {
		return err
	}
	for _, f := range ParallelPassiveFiles() {
		if err := protectedDirectory(filepath.Dir(f.Path), 0, 0, 0755); err != nil {
			return err
		}
		if prior, err := Snapshot(f); err != nil {
			return err
		} else if prior.Exists && string(prior.Data) != string(f.Data) {
			return errors.New("foreign passive unit barrier")
		}
		if err := Write(f); err != nil {
			return err
		}
	}
	_, err := run(ctx, "/usr/bin/systemctl", "daemon-reload")
	return err
}
func parallelUnitsStopped(ctx context.Context, run commandRunner) error {
	for _, unit := range []string{"cloud-8021x.service", "freeradius.service", "step-ca.service", "step-ca-rsa.service", "datadog-agent.service", "datadog-agent-ddot.service"} {
		out, err := run(ctx, "/usr/bin/systemctl", "show", unit, "--property=LoadState", "--property=ActiveState", "--property=MainPID")
		fields := map[string]string{}
		for _, line := range strings.Split(string(out), "\n") {
			if line != "" {
				k, v, ok := strings.Cut(line, "=")
				if !ok || fields[k] != "" {
					return errors.New("ambiguous parallel service state")
				}
				fields[k] = v
			}
		}
		if err != nil || fields["LoadState"] == "not-found" {
			if fields["LoadState"] != "not-found" {
				return errors.New("parallel service state unavailable")
			}
			for _, base := range []string{"/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"} {
				if _, e := os.Lstat(filepath.Join(base, unit)); !errors.Is(e, os.ErrNotExist) {
					return errors.New("unloaded owned service has ambiguous installed files")
				}
			}
		}
		if fields["ActiveState"] != "inactive" || fields["MainPID"] != "0" {
			return errors.New("parallel preparation requires positively stopped production services")
		}
	}
	return nil
}

// PassiveRadius validates installed native configuration without starting any
// service, contacting Fleet, opening production listeners or writing a CA DB.
// This is a preparation backend, not a production readiness assertion.
type PassiveRadius struct{ Backend *RadiusBackend }

func (b *PassiveRadius) Running(ctx context.Context) (bool, error) {
	return false, parallelUnitsStopped(ctx, execute)
}
func (b *PassiveRadius) PeerReady(context.Context) error {
	return errors.New("passive preparation cannot assert production peer readiness")
}
func (b *PassiveRadius) Validate(ctx context.Context) error { return b.Backend.Validate(ctx) }
func (b *PassiveRadius) Activate(ctx context.Context) error {
	return parallelUnitsStopped(ctx, execute)
}
func (b *PassiveRadius) Healthy(ctx context.Context) error { return parallelUnitsStopped(ctx, execute) }
