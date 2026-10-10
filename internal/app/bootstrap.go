package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/CampusTech/cloud-8021x/internal/adapters/gcp"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
)

func renewalPlan(cfg config.Config, o RunOptions) error {
	if err := cfg.ValidateBootstrap(); err != nil {
		return err
	}
	if o.Output == nil {
		return nil
	}
	return json.NewEncoder(o.Output).Encode(map[string]any{"dry_run": true, "steps": []string{"validate-preserved-ca-and-server-cache", "shared-maintenance", "renew-due-fixed-server-and-loopback-webhook-identities", "persist-last-known-good", "validate-native-config", "authenticate-peer-readiness", "activate-and-verify"}})
}
func protectedConfiguration(cfg config.Config, o RunOptions) (config.Config, error) {
	if os.Geteuid() != 0 {
		if o.DryRun {
			return cfg, nil
		}
		return config.Config{}, errors.New("protected operation requires root")
	}
	if o.ConfigFile != privilegedConfigFile {
		return config.Config{}, errors.New("root operation requires fixed protected configuration")
	}
	if o.Incoming {
		return readFixedProtectedConfig("/var/cache/cloud-8021x/artifacts/config.yaml")
	}
	return readProtectedSourceConfig()
}
func bootstrapCredentials(ctx context.Context, cfg config.Config) (*gcp.Client, map[string][]byte, error) {
	cloud, e := gcp.NewRoot(cfg.Bootstrap.Project, cfg.Bootstrap.ProjectNumber)
	if e != nil {
		return nil, nil, e
	}
	credentials := map[string][]byte{}
	for _, ref := range cfg.Bootstrap.Secrets {
		value, e := cloud.Latest(ctx, ref.Resource)
		if e != nil {
			return nil, nil, errors.New("required protected credential unavailable")
		}
		credentials[ref.File] = value
	}
	return cloud, credentials, nil
}
func credentialLayout(cfg config.Config, a host.Accounts) []host.File {
	files := make([]host.File, 0, len(cfg.Bootstrap.Secrets)+2)
	for _, ref := range cfg.Bootstrap.Secrets {
		uid, gid := 0, 0
		switch ref.Owner {
		case "runtime":
			uid, gid = a.RuntimeUID, a.RuntimeGID
		case "collector":
			uid, gid = a.CollectorUID, a.CollectorGID
		}
		files = append(files, host.File{Path: ref.File, UID: uid, GID: gid, Mode: 0600})
	}
	return files
}
func bootCredentialLayout(cfg config.Config, a host.Accounts) []host.File {
	return append(credentialLayout(cfg, a), host.File{Path: "/run/cloud-8021x/credentials/webhook.key", UID: a.RuntimeUID, GID: a.RuntimeGID, Mode: 0600}, host.File{Path: "/run/cloud-8021x-collector/datadog.env", UID: a.CollectorUID, GID: a.CollectorGID, Mode: 0600})
}
func credentialFiles(cfg config.Config, values map[string][]byte, a host.Accounts) ([]host.File, error) {
	files := credentialLayout(cfg, a)
	for i := range files {
		file := &files[i]
		data, ok := values[file.Path]
		if !ok || len(data) == 0 {
			return nil, errors.New("credential candidate missing")
		}
		file.Data = data
		if file.Path == cfg.Policy.ClassSigningKey.File {
			old, e := host.Snapshot(*file)
			if e != nil {
				return nil, e
			}
			if old.Exists && !bytes.Equal(old.Data, data) {
				return nil, errors.New("shared Class key differs from installed bytes; explicit migration required")
			}
		}
	}
	return files, nil
}
func refreshRootCredentials(ctx context.Context, cfg config.Config, o RunOptions) error {
	cfg, e := protectedConfiguration(cfg, o)
	if e != nil {
		return e
	}
	if e = cfg.ValidateBootstrap(); e != nil {
		return e
	}
	if o.DryRun {
		if o.Output == nil {
			return nil
		}
		return json.NewEncoder(o.Output).Encode(map[string]any{"dry_run": true, "steps": []string{"validate-protected-credential-cache", "restore-boot-credentials", "install-runtime-metadata"}})
	}
	accounts, e := host.ReadAccounts()
	if e != nil {
		return e
	}
	if e = host.PrepareDirectories(accounts); e != nil {
		return e
	}
	if e = host.RestoreBootCredentials(bootCredentialLayout(cfg, accounts)); e != nil {
		return e
	}
	return host.InstallMetadata(ctx, accounts.RuntimeUID)
}

type bootstrapOutcome struct {
	Operation    string `json:"operation"`
	Changed      bool   `json:"changed"`
	Installation string `json:"installation,omitempty"`
}

func withBootstrapReport(ctx context.Context, gate func(context.Context, string, func(context.Context) error) error, operation string, output io.Writer, action func(context.Context, *bootstrapOutcome) error) error {
	outcome := bootstrapOutcome{Operation: operation}
	// Output is deliberately outside both the rollback defer and durable shared
	// maintenance completion. A closed pipe cannot undo or relabel committed work.
	if e := gate(ctx, operation, func(ctx context.Context) error { return action(ctx, &outcome) }); e != nil {
		return e
	}
	if output != nil {
		if e := json.NewEncoder(output).Encode(outcome); e != nil {
			return fmt.Errorf("%s completed; output reporting failed: %w", operation, e)
		}
	}
	return nil
}
