// Package app constructs the executable's commands and delegates operations.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type Operation string

const (
	OperationServe                  Operation = "serve"
	OperationBootstrap              Operation = "bootstrap"
	OperationRefreshCredentials     Operation = "bootstrap credentials"
	OperationInventorySync          Operation = "inventory sync"
	OperationSitesSync              Operation = "sites sync"
	OperationMetricsEmit            Operation = "metrics emit"
	OperationCertificatesRenew      Operation = "certificates renew"
	OperationRadiusVerifyLeaf       Operation = "radius verify-leaf"
	OperationSourcesApply           Operation = "sources apply"
	OperationStateRecoverAuth       Operation = "state recover-auth"
	OperationStateRecoverCollection Operation = "state recover-collection"
	OperationStateFence             Operation = "state fence"
	OperationStateMigrate           Operation = "state migrate"
	OperationStateExport            Operation = "state export"
	OperationDoctor                 Operation = "doctor"
)

// ErrUnsupported is returned until the operation has a real injected service.
// A dry run must use that service's planner, not fabricate a successful operation.
var ErrUnsupported = errors.New("operation is not implemented")

type RunOptions struct {
	AuthFilename, AuthRangeSHA256 string
	AuthOffset                    int64
	LegacyGuardID                 string
	LegacyExecutionID             string
	MaintenanceAttempt            int64
	SourceWorkID                  string
	SourceGeneration              int64
	Version                       string
	Incoming                      bool
	FenceOnly                     bool
	SourceCandidateSHA256         string
	ConfigFile                    string
	VerifiedLeaf                  *VerifiedLeafOptions
	Debug                         bool
	DryRun                        bool
	Output                        io.Writer
	Logger                        *logrus.Logger
}
type Services interface {
	Run(context.Context, Operation, config.Config, RunOptions) error
}
type Options struct {
	// ProcessUID supplies the platform effective-UID lookup. Mutation services
	// independently check the actual OS UID; the executable uses os.Geteuid.
	ProcessUID func() int
	Version    string
	Services   Services
	Logger     *logrus.Logger
}

func NewCommand(options Options) *cobra.Command {
	processUID := options.ProcessUID
	if processUID == nil {
		processUID = os.Geteuid
	}
	var path string
	var debug, dryRun, incoming, fenceOnly bool
	var policyAddress string
	var maintenanceAttempt int64
	var sourceWorkID string
	var sourceGeneration int64
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
		var cfg config.Config
		var err error
		privileged := (cmd.Parent() != nil && cmd.Parent().Name() == "state") || cmd.Name() == "doctor" || (cmd.Name() == "emit" && cmd.Parent() != nil && cmd.Parent().Name() == "metrics") || cmd.Name() == "bootstrap" || (cmd.Name() == "credentials" && cmd.Parent() != nil && cmd.Parent().Name() == "bootstrap") || (cmd.Parent() != nil && ((cmd.Name() == "verify-leaf" && cmd.Parent().Name() == "radius") || (cmd.Name() == "renew" && cmd.Parent().Name() == "certificates") || (cmd.Name() == "apply" && cmd.Parent().Name() == "sources")))
		if privileged && processUID() == 0 {
			if path != privilegedConfigFile {
				return config.Config{}, errors.New("root operation requires the fixed protected application configuration")
			}
			if root.PersistentFlags().Changed("policy-address") {
				return config.Config{}, errors.New("root operation rejects listener overrides")
			}
			if incoming && cmd.Name() == "bootstrap" {
				cfg, err = readFixedProtectedConfig("/var/cache/cloud-8021x/artifacts/config.yaml")
			} else {
				cfg, err = readProtectedSourceConfig()
			}
		} else {
			cfg, err = config.LoadForOverrides(path)
		}
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
		var leaf VerifiedLeafOptions
		var sourceDigest string
		var legacyGuardID, legacyExecutionID string
		var authFilename, authRangeSHA256 string
		var authOffset int64
		cmd := &cobra.Command{Use: name, Short: string(op), Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := load(cmd)
			if err != nil {
				return err
			}
			if options.Services == nil {
				return fmt.Errorf("%s: %w", op, ErrUnsupported)
			}
			logger.WithFields(logrus.Fields{"operation": string(op), "dry_run": dryRun}).Debug("running operation")
			run := RunOptions{AuthFilename: authFilename, AuthRangeSHA256: authRangeSHA256, AuthOffset: authOffset, LegacyGuardID: legacyGuardID, LegacyExecutionID: legacyExecutionID, SourceWorkID: sourceWorkID, SourceGeneration: sourceGeneration, MaintenanceAttempt: maintenanceAttempt, Version: options.Version, Incoming: incoming, FenceOnly: fenceOnly, SourceCandidateSHA256: sourceDigest, Debug: cfg.Debug, DryRun: dryRun, Output: cmd.OutOrStdout(), Logger: logger, ConfigFile: path}
			if op == OperationRadiusVerifyLeaf {
				copy := leaf
				run.VerifiedLeaf = &copy
			}
			return options.Services.Run(cmd.Context(), op, cfg, run)
		}}
		if op == OperationStateRecoverAuth {
			cmd.Flags().StringVar(&authFilename, "file", "", "Exact native auth basename")
			cmd.Flags().StringVar(&authRangeSHA256, "sha256", "", "Exact original malformed record digest; dry-run can inspect it")
			cmd.Flags().Int64Var(&authOffset, "offset", 0, "Exact committed malformed byte offset")
			cmd.Flags().Int64Var(&maintenanceAttempt, "resume-attempt", 0, "Prove exact already-committed quarantine after lost acknowledgement")
		}
		if op == OperationStateRecoverCollection {
			cmd.Flags().Int64Var(&maintenanceAttempt, "resume-attempt", 0, "Prove only the retained committed original terminal resolution")
			cmd.Flags().StringVar(&legacyGuardID, "guard", "", "Exact imported legacy pending guard digest")
			cmd.Flags().StringVar(&legacyExecutionID, "execution-id", "", "Original Windows execution identity hint, verified against retained nonce and script")
		}
		if op == OperationStateExport {
			cmd.Flags().BoolVar(&fenceOnly, "fence-only", false, "Revoke shared work and physically fence this node for cold rollback")
			cmd.Flags().Int64Var(&maintenanceAttempt, "resume-attempt", 0, "Resume only the exact interrupted export-fence attempt")
		}
		if op == OperationStateMigrate {
			cmd.Flags().Int64Var(&maintenanceAttempt, "resume-attempt", 0, "Continue exact original committed bundle publication after helper exit proof")
		}
		if op == OperationStateFence {
			cmd.Flags().Int64Var(&maintenanceAttempt, "resume-attempt", 0, "Resume this exact expired writer fence attempt after protected quiescence proof")
		}
		if op == OperationSourcesApply {
			cmd.Flags().StringVar(&sourceWorkID, "reconcile-work", "", "Reconcile only this quarantined historical source work ID")
			cmd.Flags().Int64Var(&sourceGeneration, "generation", 0, "Exact quarantined source generation")
			cmd.Flags().Int64Var(&maintenanceAttempt, "resume-attempt", 0, "Exact prior source maintenance attempt to prove read-only")
			cmd.Flags().StringVar(&sourceDigest, "candidate-sha256", "", "Require this canonical claimed candidate digest before privileged I/O")
		}
		if op == OperationRadiusVerifyLeaf {
			cmd.Use = name + " [certificate-file session-token]"
			cmd.Flags().StringVar(&leaf.CertificateFile, "certificate-file", "", "Completed TLS verification leaf PEM filename")
			cmd.Flags().StringVar(&leaf.SessionToken, "session-token", "", "Server-generated one-use TLS session token")
			cmd.Args = func(cmd *cobra.Command, args []string) error {
				if len(args) != 0 {
					if len(args) != 2 || cmd.Flags().Changed("certificate-file") || cmd.Flags().Changed("session-token") {
						return errors.New("provide certificate-file and session-token either as two arguments or explicit flags")
					}
					leaf.CertificateFile = args[0]
					leaf.SessionToken = args[1]
				}
				return leaf.Validate()
			}
		}
		return cmd
	}
	bootstrap := operation("bootstrap", OperationBootstrap)
	bootstrap.Flags().Int64Var(&maintenanceAttempt, "resume-attempt", 0, "Prove the exact interrupted fence or pre-install preparation attempt")
	bootstrap.Flags().BoolVar(&fenceOnly, "fence-only", false, "Prepare only this node’s persistent legacy writer fence using the fixed incoming release")
	bootstrap.Flags().BoolVar(&incoming, "incoming", false, "Bootstrap the verified release from the fixed protected incoming directory")
	bootstrap.AddCommand(operation("credentials", OperationRefreshCredentials))
	root.AddCommand(operation("serve", OperationServe), bootstrap, operation("doctor", OperationDoctor), versionCmd(options.Version))
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
		}{{"recover-auth", OperationStateRecoverAuth}, {"recover-collection", OperationStateRecoverCollection}, {"fence", OperationStateFence}, {"migrate", OperationStateMigrate}, {"export", OperationStateExport}}},
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
	profileOptions := &RunOptions{Logger: logger}
	profile := profileCommand(profileOptions)
	profile.PreRunE = func(cmd *cobra.Command, _ []string) error {
		cfg, err := load(cmd)
		if err != nil {
			return err
		}
		profileOptions.DryRun = dryRun
		profileOptions.Debug = cfg.Debug
		if !cmd.Flags().Changed("signing-key-file") {
			return cmd.Flags().Set("signing-key-file", cfg.Inventory.Fleet.ChallengeSigningKey.File)
		}
		return nil
	}
	root.AddCommand(profile)
	return root
}
