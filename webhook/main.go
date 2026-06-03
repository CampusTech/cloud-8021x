package main

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:   "acme-authz-webhook",
		Short: "step-ca AUTHORIZING webhook that allows ACME/SCEP issuance only for Fleet-enrolled device serials (fail-closed).",
	}
	root.AddCommand(serveCmd())
	if err := root.Execute(); err != nil {
		logrus.WithError(err).Fatal("command failed")
	}
}

// serveCmd is a placeholder replaced in Task 7 with the real HTTP server.
func serveCmd() *cobra.Command {
	return &cobra.Command{Use: "serve", Short: "Run the authorizing webhook HTTP server."}
}
