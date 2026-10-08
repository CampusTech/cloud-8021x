package app

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/webhook/authorize"
	"github.com/CampusTech/cloud-8021x/internal/webhook/broker"
	"github.com/CampusTech/cloud-8021x/internal/webhook/config"
	"github.com/CampusTech/cloud-8021x/internal/webhook/fleet"
	"github.com/CampusTech/cloud-8021x/internal/webhook/server"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// NewCompatibilityCommand retains the old webhook environment and command contract.
// Both executable entrypoints reuse the same protocol packages and challenge logic.
func NewCompatibilityCommand(version string) *cobra.Command {
	root := &cobra.Command{
		Use:   "acme-authz-webhook",
		Short: "step-ca authorizing webhook and optional Fleet SCEP challenge broker (fail-closed).",
	}
	root.AddCommand(serveCmd())
	root.AddCommand(versionCmd(version))
	root.AddCommand(challengeCmd())
	return root
}

func versionCmd(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the webhook version and exit.",
		Run: func(cmd *cobra.Command, _ []string) {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), version)
		},
	}
}

func serveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the mutual-TLS authorizing webhook server.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			var roots []byte
			for _, name := range strings.Split(cfg.ClientCAFiles, ":") {
				data, err := os.ReadFile(name)
				if err != nil {
					return fmt.Errorf("read webhook client CA: %w", err)
				}
				roots = append(roots, data...)
				roots = append(roots, '\n')
			}
			tlsConfig, err := server.ClientTLSConfig(roots, strings.Split(cfg.ClientDNSNames, ","))
			if err != nil {
				return err
			}
			fc := fleet.New(cfg.FleetBaseURL, cfg.FleetToken, cfg.FleetTimeout)
			authz := authorize.New(fc, cfg.AllowLabel)
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			decider := server.DeciderFunc(func(identity string) bool { return authz.Decide(ctx, identity) })
			h := server.NewMutualTLS(cfg.SCEPChallengeSigningKey, decider)
			if cfg.SCEPCertificateInventory {
				h = server.NewMutualTLSInventory(cfg.SCEPChallengeSigningKey, cfg.SCEPBrokerProvisioner, decider)
			}
			// Bind to loopback only — step-ca calls it over localhost on the
			// same VM. Defense-in-depth in case host firewall rules ever drift.
			logrus.WithField("port", cfg.Port).Info("authorizing webhook listening")
			srv := &http.Server{
				Addr: "127.0.0.1:" + cfg.Port, Handler: h,
				ReadHeaderTimeout: 5 * time.Second,
				TLSConfig:         tlsConfig,
			}
			servers := []*http.Server{srv}
			if cfg.SCEPCertificateInventory {
				brokerHandler, err := broker.New(cfg.BrokerOptions())
				if err != nil {
					return err
				}
				logrus.WithField("port", cfg.SCEPBrokerPort).Info("Fleet SCEP challenge broker listening")
				// GCLB terminates public TLS and connects by HTTPS. Firewall permits only
				// GFE/health checks; this separate server deliberately has no mTLS or authorize route.
				servers = append(servers, &http.Server{Addr: ":" + cfg.SCEPBrokerPort, Handler: brokerHandler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}})
			}
			return serveServers(ctx, servers, cfg.TLSCertFile, cfg.TLSKeyFile)
		},
	}
}
