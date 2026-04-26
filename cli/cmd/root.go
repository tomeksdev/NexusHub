// Package cmd owns the CLI's Cobra commands. The entry point is
// Execute(); subcommands register themselves via init() on this
// package so main.go stays at a single call.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Build metadata. Populated via -ldflags at release time; defaults
// keep `go run` usable during development.
var (
	version = "dev"
	commit  = "unknown"
)

// Persistent flags surfaced on every subcommand.
var (
	flagConfig string
	flagServer string
)

var rootCmd = &cobra.Command{
	Use:   "nexushub",
	Short: "NexusHub CLI — WireGuard VPN management",
	Long: `nexushub is the command-line interface to the NexusHub API.
Use it for interactive administration or for unattended automation via
an API key configured in ~/.config/nexushub/config.yaml.`,
	SilenceUsage:  true, // don't print full usage on every runtime error
	SilenceErrors: true, // we print errors ourselves for nicer formatting
}

func init() {
	rootCmd.PersistentFlags().StringVar(&flagConfig, "config", "",
		"path to config file (default: $XDG_CONFIG_HOME/nexushub/config.yaml)")
	rootCmd.PersistentFlags().StringVar(&flagServer, "server", "",
		"override the API URL stored in the config")
}

// Execute runs the root command. main.go calls this.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// SetBuildInfo is wired from main at link time when -ldflags populates
// the package-level vars. Kept as a setter (rather than importing
// main's vars) so the `cmd` package can be unit-tested without a
// build-time hook.
func SetBuildInfo(v, c string) {
	if v != "" {
		version = v
	}
	if c != "" {
		commit = c
	}
}
