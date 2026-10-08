// Package app constructs the executable's commands and delegates operations.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type Operation string

const (
	OperationServe             Operation = "serve"
	OperationBootstrap         Operation = "bootstrap"
	OperationInventorySync     Operation = "inventory sync"
	OperationSitesSync         Operation = "sites sync"
	OperationMetricsEmit       Operation = "metrics emit"
	OperationCertificatesRenew Operation = "certificates renew"
	OperationRadiusVerifyLeaf  Operation = "radius verify-leaf"
	OperationSourcesApply      Operation = "sources apply"
	OperationStateMigrate      Operation = "state migrate"
	OperationStateExport       Operation = "state export"
	OperationDoctor            Operation = "doctor"
)

// ErrUnsupported is returned until the operation has a real injected service.
// A dry run must use that service's planner, not fabricate a successful operation.
var ErrUnsupported = errors.New("operation is not implemented")

type RunOptions struct {
	Debug  bool
	DryRun bool
	Output io.Writer
	Logger *logrus.Logger
}
type Services interface {
	Run(context.Context, Operation, config.Config, RunOptions) error
}
type Options struct {
	Version  string
	Services Services
	Logger   *logrus.Logger
}

func NewCommand(options Options) *cobra.Command {
	var path string
	var debug, dryRun bool
	var policyAddress string
	logger := options.Logger
	if logger == nil {
		logger = logrus.New()
		logger.SetFormatter(&logrus.JSONFormatter{})
	}
	root := &cobra.Command{Use: "cloud-8021x", Short: "Cloud 802.1X daemon and protected operations", SilenceUsage: true, SilenceErrors: true}
	root.PersistentFlags().StringVar(&path, "config", "/etc/cloud-8021x/config.yaml", "Versioned non-secret YAML configuration")
	root.PersistentFlags().BoolVar(&debug, "debug", false, "Log safe structured diagnostics")
	root.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "Validate and plan without mutating state")
	root.PersistentFlags().StringVar(&policyAddress, "policy-address", "", "Override loopback policy listener address")
	load := func(cmd *cobra.Command) (config.Config, error) {
		if err := cmd.Context().Err(); err != nil {
			return config.Config{}, err
		}
		cfg, err := config.LoadForOverrides(path)
		if err != nil {
			return config.Config{}, err
		}
		if root.PersistentFlags().Changed("debug") {
			cfg.Debug = debug
		}
		if root.PersistentFlags().Changed("policy-address") {
			cfg.Listeners.Policy.Address = policyAddress
		}
		if err := cfg.Validate(); err != nil {
			return config.Config{}, err
		}
		logger.SetOutput(cmd.ErrOrStderr())
		logger.SetLevel(logrus.InfoLevel)
		if cfg.Debug {
			logger.SetLevel(logrus.DebugLevel)
		}
		return cfg, nil
	}
	operation := func(name string, op Operation) *cobra.Command {
		return &cobra.Command{Use: name, Short: string(op), Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := load(cmd)
			if err != nil {
				return err
			}
			if options.Services == nil {
				return fmt.Errorf("%s: %w", op, ErrUnsupported)
			}
			logger.WithFields(logrus.Fields{"operation": string(op), "dry_run": dryRun}).Debug("running operation")
			return options.Services.Run(cmd.Context(), op, cfg, RunOptions{Debug: cfg.Debug, DryRun: dryRun, Output: cmd.OutOrStdout(), Logger: logger})
		}}
	}
	root.AddCommand(operation("serve", OperationServe), operation("bootstrap", OperationBootstrap), operation("doctor", OperationDoctor), versionCmd(options.Version))
	for _, group := range []struct {
		name    string
		actions []struct {
			name string
			op   Operation
		}
	}{
		{"inventory", []struct {
			name string
			op   Operation
		}{{"sync", OperationInventorySync}}},
		{"sites", []struct {
			name string
			op   Operation
		}{{"sync", OperationSitesSync}}},
		{"metrics", []struct {
			name string
			op   Operation
		}{{"emit", OperationMetricsEmit}}},
		{"certificates", []struct {
			name string
			op   Operation
		}{{"renew", OperationCertificatesRenew}}},
		{"radius", []struct {
			name string
			op   Operation
		}{{"verify-leaf", OperationRadiusVerifyLeaf}}},
		{"sources", []struct {
			name string
			op   Operation
		}{{"apply", OperationSourcesApply}}},
		{"state", []struct {
			name string
			op   Operation
		}{{"migrate", OperationStateMigrate}, {"export", OperationStateExport}}},
	} {
		parent := &cobra.Command{Use: group.name}
		for _, a := range group.actions {
			parent.AddCommand(operation(a.name, a.op))
		}
		root.AddCommand(parent)
	}
	cfgCmd := &cobra.Command{Use: "config"}
	cfgCmd.AddCommand(&cobra.Command{Use: "validate", Short: "Validate configuration and secret references without opening secrets", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if _, err := load(cmd); err != nil {
			return err
		}
		_, err := fmt.Fprintln(cmd.OutOrStdout(), "Configuration valid (schema_version 1); secret file contents were not read.")
		return err
	}})
	root.AddCommand(cfgCmd)
	challengeOptions := &RunOptions{Logger: logger}
	challenge := challengeCommand(true, challengeOptions)
	challenge.PreRunE = func(cmd *cobra.Command, _ []string) error {
		cfg, err := load(cmd)
		if err != nil {
			return err
		}
		challengeOptions.Debug = cfg.Debug
		challengeOptions.DryRun = dryRun
		if !cmd.Flags().Changed("signing-key-file") {
			if err := cmd.Flags().Set("signing-key-file", cfg.Inventory.Fleet.ChallengeSigningKey.File); err != nil {
				return err
			}
		}
		if !cmd.Flags().Changed("provisioner") {
			if err := cmd.Flags().Set("provisioner", cfg.Inventory.Fleet.SCEPProvisioner); err != nil {
				return err
			}
		}
		keyFile, err := cmd.Flags().GetString("signing-key-file")
		if err != nil {
			return err
		}
		return (config.SecretRef{File: keyFile}).Validate("SCEP challenge signing key", true)
	}
	root.AddCommand(challenge)
	return root
}
