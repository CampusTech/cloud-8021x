package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func main() {
	if err := newScenarioCommand(os.Stdin, os.Stdout).Execute(); err != nil {
		logger := logrus.New()
		logger.SetOutput(os.Stderr)
		logger.WithField("phase", "cli").Error("scenario input or operation refused")
		os.Exit(1)
	}
}
func newScenarioCommand(in io.Reader, out io.Writer) *cobra.Command {
	cmd := &cobra.Command{Use: "task11-scenarios", SilenceUsage: true, SilenceErrors: true, Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error { return errors.New("closed scenario subcommand required") }}
	cmd.SetIn(in)
	cmd.SetOut(out)
	admit := &cobra.Command{Use: "admit", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		raw, e := readClientBody(in, 256<<10)
		if e != nil {
			return e
		}
		defer clear(raw)
		projection, e := admitNASInput(raw)
		if e != nil {
			return e
		}
		public, e := json.Marshal(projection)
		if e != nil || len(public) > 4096 {
			return errors.New("bounded public admission projection unavailable")
		}
		if _, e = out.Write(append(public, '\n')); e != nil {
			return errors.New("public admission projection write failed")
		}
		return nil
	}}
	nas := &cobra.Command{Use: "nas ACTION", Args: cobra.ExactArgs(1), RunE: func(command *cobra.Command, args []string) error {
		raw, e := readClientBody(in, 256<<10)
		if e != nil {
			return e
		}
		defer clear(raw)
		body, e := runNAS(command.Context(), args[0], raw)
		if e != nil {
			return e
		}
		if _, e = out.Write(append(body, '\n')); e != nil {
			return errors.New("public native body write failed")
		}
		return nil
	}}
	var planPin, phase string
	var dryRun, debug bool
	run := &cobra.Command{Use: "run CASE", Args: cobra.ExactArgs(1), RunE: func(command *cobra.Command, args []string) error {
		if e := validateRunCase(args[0], phase); e != nil {
			return e
		}
		if !shaPattern.MatchString(planPin) {
			return errors.New("independent exact plan pin required")
		}
		if debug {
			logger := logrus.New()
			logger.SetOutput(os.Stderr)
			logger.SetLevel(logrus.DebugLevel)
			logger.WithFields(logrus.Fields{"case": args[0], "phase": phase, "dry_run": dryRun}).Debug("closed scenario invocation")
		}
		var body []byte
		var e error
		if dryRun {
			raw, readErr := readClientBody(in, 64<<10)
			if readErr != nil {
				return readErr
			}
			defer clear(raw)
			body, e = dryRunScenario(args[0], planPin, phase, raw)
		} else {
			body, e = runOuter(command.Context(), args[0], planPin, phase)
		}
		if e != nil {
			return e
		}
		if _, e = out.Write(append(body, '\n')); e != nil {
			return errors.New("bounded measured driver coordinates write failed")
		}
		return nil
	}}
	run.Flags().StringVar(&planPin, "plan-sha256", "", "Independent exact protected case plan SHA256")
	run.Flags().StringVar(&phase, "phase", "", "Explicit original, adopted or passive CA phase")
	run.Flags().BoolVar(&dryRun, "dry-run", false, "Validate exact private stdin plan without installed operations")
	run.Flags().BoolVar(&debug, "debug", false, "Log only sanitized closed invocation fields")
	cmd.AddCommand(admit, nas, run, prepareCommand(out))
	return cmd
}
