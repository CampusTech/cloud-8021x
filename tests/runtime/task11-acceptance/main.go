package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func command() *cobra.Command {
	var dryRun, debug bool
	root := &cobra.Command{Use: "task11-acceptance", Short: "Development-only synthetic guest acceptance controller", SilenceErrors: true, SilenceUsage: true}
	root.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "Print the closed plan without reading guest state or executing anything")
	root.PersistentFlags().BoolVar(&debug, "debug", false, "Include public stage diagnostics only")
	root.AddCommand(&cobra.Command{Use: "stage", Short: "Run the root-private requested stage in the single delegated service", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if dryRun {
			return errors.New("select an explicit stage with --dry-run; the service request is a protected guest input")
		}
		return requestedStage(cmd.Context())
	}})
	for _, stage := range []string{"keys", "prepare", "cutover", "deactivate", "proofs", "resume", "observe", "recover", "verify-cloud"} {
		root.AddCommand(&cobra.Command{Use: stage, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			plan, err := stagePlan(cmd.Name())
			if err != nil {
				return err
			}
			if dryRun {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(plan)
			}
			logger := logrus.New()
			logger.SetOutput(cmd.ErrOrStderr())
			if debug {
				logger.SetLevel(logrus.DebugLevel)
			}
			return executeStage(cmd.Context(), cmd.Name(), logger)
		}})
	}
	root.AddCommand(&cobra.Command{Use: "node ACTION [ARGS...]", Hidden: true, Args: cobra.MinimumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if dryRun {
			return errors.New("node transport has no dry-run side effects")
		}
		return nodeCommand(cmd.Context(), args, cmd.InOrStdin(), cmd.OutOrStdout())
	}})
	root.AddCommand(&cobra.Command{Use: "source-writer", Hidden: true, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if dryRun {
			return nil
		}
		return sourceWriter(cmd.Context())
	}})
	root.AddCommand(&cobra.Command{Use: "source-policy", Short: "Development-only legacy-compatible source endpoint", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if dryRun {
			return nil
		}
		return sourcePolicy(cmd.Context())
	}})
	root.AddCommand(&cobra.Command{Use: "source-render", Short: "Render actual shipping native configuration as an uninstalled private source candidate", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		if dryRun {
			return nil
		}
		return sourceRender()
	}})
	root.AddCommand(&cobra.Command{Use: "seed", Short: "Generate synthetic original CA/cache material in the enrolled guest control directory", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if dryRun {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "synthetic CA/cache seed only; no product receipt keys, fences, accounting or activation markers")
			return err
		}
		return seedGuest()
	}})
	return root
}
func main() {
	if err := command().Execute(); err != nil {
		logrus.WithField("error", err.Error()).Error("development acceptance stopped")
		os.Exit(1)
	}
}
