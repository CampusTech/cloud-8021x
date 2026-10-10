package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/CampusTech/cloud-8021x/internal/app"
)

// version is set by release builds with -ldflags '-X main.version=...'.
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	command := app.NewCommand(app.Options{Version: version, Services: app.NewRuntimeServices()})
	if err := command.ExecuteContext(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
