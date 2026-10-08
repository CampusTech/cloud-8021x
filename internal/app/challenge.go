package app

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/webhook/challenge"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// challengeCmd is an administrator/MDM-side issuer. It deliberately exposes no
// unauthenticated HTTP minting endpoint and never accepts a signing key in argv.
func challengeCmd() *cobra.Command { return challengeCommand(false) }

func challengeCommand(inheritFlags bool) *cobra.Command {
	var identity, provisioner, output, keyFile string
	var ttl time.Duration
	var dryRun, debug bool
	cmd := &cobra.Command{
		Use:   "scep-challenge",
		Short: "Issue a device-bound SCEP challenge for trusted per-device MDM delivery",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := cmd.Context().Err(); err != nil {
				return err
			}
			if inheritFlags {
				dryRun, _ = cmd.Flags().GetBool("dry-run")
				debug, _ = cmd.Flags().GetBool("debug")
			}
			var key []byte
			if !inheritFlags {
				key = []byte(os.Getenv("SCEP_CHALLENGE_SIGNING_KEY"))
			}
			if keyFile != "" {
				data, err := os.ReadFile(keyFile)
				if err != nil {
					return fmt.Errorf("read signing key: %w", err)
				}
				key = []byte(strings.TrimSpace(string(data)))
			}
			token, err := challenge.Issue(key, identity, provisioner, time.Now(), ttl)
			if err != nil {
				return err
			}
			if dryRun {
				_, err := fmt.Fprintln(cmd.OutOrStdout(), "Valid device binding and TTL; no challenge written.")
				return err
			}
			if output == "" {
				return fmt.Errorf("--out is required; challenges must be delivered privately")
			}
			file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return fmt.Errorf("create challenge file: %w", err)
			}
			_, writeErr := file.WriteString(token + "\n")
			closeErr := file.Close()
			if writeErr != nil {
				return fmt.Errorf("write challenge file: %w", writeErr)
			}
			if closeErr != nil {
				return closeErr
			}
			if debug {
				logrus.WithFields(logrus.Fields{"provisioner": provisioner, "ttl": ttl.String()}).Info("SCEP challenge written")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&identity, "identity", "", "Device identity selected from trusted MDM inventory")
	cmd.Flags().StringVar(&provisioner, "provisioner", "", "Exact step-ca SCEP provisioner name")
	cmd.Flags().StringVar(&output, "out", "", "New private output file (never overwrites)")
	cmd.Flags().StringVar(&keyFile, "signing-key-file", "", "Server-only signing key file; otherwise SCEP_CHALLENGE_SIGNING_KEY")
	cmd.Flags().DurationVar(&ttl, "ttl", 15*time.Minute, "Enrollment validity, maximum 24h; renewal needs a fresh challenge")
	if !inheritFlags {
		cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Validate inputs without writing a challenge")
		cmd.Flags().BoolVar(&debug, "debug", false, "Log non-secret issuance metadata")
	}
	return cmd
}
