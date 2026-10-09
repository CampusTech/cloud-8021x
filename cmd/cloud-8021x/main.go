package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/CampusTech/cloud-8021x/internal/app"
)

// version is set by release builds with -ldflags '-X main.version=...'.
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	command := app.NewCommand(app.Options{Version: version, Services: app.NewRuntimeServices()})
	switch filepath.Base(os.Args[0]) {
	case "acme-authz-webhook", "acme-authz-webhook-linux-amd64", "acme-authz-webhook-linux-arm64":
		command = app.NewCompatibilityCommand(version)
	}
	if err := command.ExecuteContext(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
