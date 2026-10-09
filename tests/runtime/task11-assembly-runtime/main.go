// Development-only preparation tool. It emits private candidates, never installs them.
package main

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func command() *cobra.Command {
	var planPath, planSHA, out string
	var dry, debug bool
	c := &cobra.Command{Use: "task11-assembly-runtime", SilenceErrors: true, SilenceUsage: true, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		raw, err := readPrivatePinned(planPath, planSHA, 64<<10)
		if err != nil {
			return invalidCandidate(err)
		}
		var p plan
		if domain.DecodeJSONStrict(raw, &p) != nil {
			return errors.New("strict assembly plan required")
		}
		candidate, err := loadAssembly(p)
		if err != nil {
			return invalidCandidate(err)
		}
		if !dry {
			if err = writeCandidates(out, candidate); err != nil {
				return invalidCandidate(err)
			}
		}
		if debug {
			logrus.WithField("candidate_files", len(candidate.Files)).Debug("private assembly prepared")
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
			Schema         int
			CandidateFiles int
			Installed      bool
			DryRun         bool
		}{1, len(candidate.Files), false, dry})
	}}
	c.Flags().StringVar(&planPath, "plan", "", "independently reviewed local private plan")
	c.Flags().StringVar(&planSHA, "plan-sha256", "", "exact independently pinned plan bytes")
	c.Flags().StringVar(&out, "out", "", "new exclusive private candidate directory")
	c.Flags().BoolVar(&dry, "dry-run", false, "validate pinned inputs and render without writing")
	c.Flags().BoolVar(&debug, "debug", false, "public counts only")
	return c
}
func main() {
	if err := command().Execute(); err != nil {
		logrus.WithField("error", err.Error()).Error("assembly preparation refused")
		os.Exit(1)
	}
}
