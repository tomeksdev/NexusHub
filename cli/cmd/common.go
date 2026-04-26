package cmd

import (
	"github.com/spf13/cobra"

	"github.com/tomeksdev/NexusHub/cli/internal/client"
	"github.com/tomeksdev/NexusHub/cli/internal/config"
)

// clientFromFlags loads the config file and constructs an authenticated
// client. Every subcommand that talks to the API calls this; keeping it
// centralized means a fix to the auth-header flow lands everywhere.
func clientFromFlags(_ *cobra.Command) (*client.Client, *config.File, error) {
	path, err := config.Path(flagConfig)
	if err != nil {
		return nil, nil, err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, nil, err
	}
	return client.New(cfg, flagServer), cfg, nil
}

// addOutputFlags registers --json on a command. Subcommands read
// jsonOutput when deciding between Table and JSON.
func addOutputFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "emit the raw JSON response instead of a table")
}

// jsonOutput is shared across list commands — each sets it via
// addOutputFlags and reads it when choosing the output format.
var jsonOutput bool
