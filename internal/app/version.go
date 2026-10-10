package app

import (
	"fmt"

	"github.com/spf13/cobra"
)

func versionCmd(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the application version and exit.",
		Run: func(cmd *cobra.Command, _ []string) {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), version)
		},
	}
}
