package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/CampusTech/cloud-8021x/webhook/internal/authorize"
	"github.com/CampusTech/cloud-8021x/webhook/internal/config"
	"github.com/CampusTech/cloud-8021x/webhook/internal/fleet"
	"github.com/CampusTech/cloud-8021x/webhook/internal/server"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// version is injected at build time via -ldflags "-X main.version=<v>".
// Defaults to "dev" for local builds. The VM startup script compares
// `acme-authz-webhook version` against the pinned release to decide whether to
// re-download.
var version = "dev"

func main() {
	root := &cobra.Command{
		Use:   "acme-authz-webhook",
		Short: "step-ca AUTHORIZING webhook that allows ACME/SCEP issuance only for Fleet-enrolled device serials (fail-closed).",
	}
	root.AddCommand(serveCmd())
	root.AddCommand(versionCmd())
	if err := root.Execute(); err != nil {
		logrus.WithError(err).Fatal("command failed")
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the webhook version and exit.",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Println(version)
		},
	}
}

func serveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the authorizing webhook HTTP server.",
		RunE: func(_ *cobra.Command, _ []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			fc := fleet.New(cfg.FleetBaseURL, cfg.FleetToken, cfg.FleetTimeout)
			authz := authorize.New(fc, cfg.AllowLabel)
			h := server.New(cfg.SigningSecret, server.DeciderFunc(func(serial string) bool {
				return authz.Decide(context.Background(), serial)
			}))
			logrus.WithField("port", cfg.Port).Info("authorizing webhook listening")
			return http.ListenAndServe(":"+cfg.Port, h)
		},
	}
}
