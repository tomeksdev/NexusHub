package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the CLI version and exit",
	Run: func(cmd *cobra.Command, _ []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "nexushub %s (commit %s)\n", version, commit)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
