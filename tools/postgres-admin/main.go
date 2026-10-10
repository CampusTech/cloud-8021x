// The administrator tool is built only on a private provisioning runner. It is
// not included in daemon release archives or installed on RADIUS VMs.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/provisioning"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func command() *cobra.Command {
	var path string
	var terraform, dryRun, debug bool
	root := &cobra.Command{Use: "cloud8021x-postgres-admin", SilenceUsage: true, SilenceErrors: true}
	root.PersistentFlags().StringVar(&path, "config", "", "reviewed nonsecret JSON configuration")
	root.PersistentFlags().BoolVar(&debug, "debug", false, "enable structured administrator diagnostics")
	load := func(cmd *cobra.Command) (provisioning.Config, error) {
		var data []byte
		var e error
		if terraform {
			if path != "" {
				return provisioning.Config{}, errors.New("terraform input and config file are exclusive")
			}
			var query map[string]string
			decoder := json.NewDecoder(io.LimitReader(cmd.InOrStdin(), 131073))
			if decoder.Decode(&query) != nil || len(query) != 1 {
				return provisioning.Config{}, errors.New("invalid Terraform prerequisite input")
			}
			data = []byte(query["config"])
		} else {
			if path == "" {
				return provisioning.Config{}, errors.New("reviewed --config required")
			}
			f, err := os.Open(path)
			if err != nil {
				return provisioning.Config{}, errors.New("administrator configuration unavailable")
			}
			defer func() { _ = f.Close() }()
			data, e = io.ReadAll(io.LimitReader(f, 65537))
			if e != nil {
				return provisioning.Config{}, errors.New("administrator configuration unreadable")
			}
		}
		if debug {
			logrus.SetLevel(logrus.DebugLevel)
			logrus.WithField("operation", cmd.Name()).Debug("checking private database prerequisites")
		}
		return provisioning.Decode(data)
	}
	check := &cobra.Command{Use: "check", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		c, e := load(cmd)
		if e != nil {
			return e
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		result, e := provisioning.Check(ctx, c)
		if e != nil {
			return e
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
	}}
	check.Flags().BoolVar(&terraform, "terraform", false, "read Terraform external-data JSON from stdin")
	check.Flags().Bool("dry-run", true, "verification is always read-only")
	harden := &cobra.Command{Use: "harden-ca-acl", Args: cobra.NoArgs, Short: "Apply only a separately approved exact CA ACL inventory", RunE: func(cmd *cobra.Command, _ []string) error {
		c, e := load(cmd)
		if e != nil {
			return e
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		if e = provisioning.Harden(ctx, c, !dryRun); e != nil {
			return e
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]bool{"dry_run": dryRun, "verified": true})
	}}
	harden.Flags().BoolVar(&dryRun, "dry-run", true, "only verify the reviewed change; set false only for an explicitly approved operation")
	root.AddCommand(check, harden)
	return root
}
func main() {
	logrus.SetFormatter(&logrus.JSONFormatter{})
	if e := command().Execute(); e != nil {
		logrus.WithError(e).Error("private database prerequisite failed")
		os.Exit(1)
	}
}
