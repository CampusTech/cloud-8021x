// Legacy executable alias. Protocol implementation lives in the root module.
package main

import (
	"os"

	"github.com/CampusTech/cloud-8021x/internal/app"
)

var version = "dev"

func main() {
	if err := app.NewCompatibilityCommand(version).Execute(); err != nil {
		os.Exit(1)
	}
}
