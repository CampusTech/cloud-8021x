// Development-only fixed original-blue schema initializer. Never installed by the product.
package main

import (
	"encoding/json"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func command() *cobra.Command {
	var dry, debug bool
	var pin string
	c := &cobra.Command{Use: "task11-blue-migration", SilenceUsage: true, SilenceErrors: true, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		p, err := loadInputs(pin)
		if err != nil {
			return err
		}
		if !dry {
			unlock, e := acquireLock()
			if e != nil {
				return e
			}
			defer unlock()
			p, e = loadInputs(pin)
			if e != nil {
				return e
			}
		}
		if err = execute(cmd.Context(), p, dry); err != nil {
			return err
		}
		if debug {
			logrus.WithFields(logrus.Fields{"database": database, "dry_run": dry}).Info("blue fixture schema operation finished")
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
			Schema           int
			Database         string
			DryRun, Migrated bool
		}{1, database, dry, !dry})
	}}
	c.Flags().StringVar(&pin, "plan-sha256", "", "independently pinned fixed root-private plan")
	c.Flags().BoolVar(&dry, "dry-run", false, "validate protected inputs without constructing a pool")
	c.Flags().BoolVar(&debug, "debug", false, "public operation identity only")
	return c
}
func main() {
	if err := command().Execute(); err != nil {
		logrus.WithField("error", err.Error()).Error("blue fixture migration refused")
		os.Exit(1)
	}
}
