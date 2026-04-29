package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/tomeksdev/NexusHub/cli/internal/client"
	"github.com/tomeksdev/NexusHub/cli/internal/config"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check that the CLI can reach the API with current credentials",
	Long: `Performs three probes and prints a one-line verdict for each:

  1. Config file — can it be loaded?
  2. Health      — does /api/v1/health answer?
  3. Auth        — does the stored credential accept a privileged call?

Intended as the first thing to run after 'login' or when triaging
"nothing works". Exits non-zero when any probe fails.`,
	RunE: runDoctor,
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}

func runDoctor(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()
	path, err := config.Path(flagConfig)
	if err != nil {
		fmt.Fprintf(out, "✗ config path   — %v\n", err)
		return err
	}
	fmt.Fprintf(out, "✓ config path   — %s\n", path)

	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(out, "✗ config load   — %v\n", err)
		return err
	}
	fmt.Fprintf(out, "✓ config load   — api_url=%s\n", cfg.APIURL)

	cli := client.New(cfg, flagServer)
	health, err := cli.Health()
	if err != nil {
		fmt.Fprintf(out, "✗ /health       — %v\n", err)
		return err
	}
	fmt.Fprintf(out, "✓ /health       — %s\n", health.Status)

	// Probe an authenticated endpoint. We pick /interfaces because it's
	// cheap and available to every role — a 401 means the token is
	// stale (or missing), a 403 means the account lacks the role the
	// server requires for that endpoint, both are actionable.
	if _, err := cli.ListInterfaces(1); err != nil {
		var apiErr *client.Error
		if errors.As(err, &apiErr) {
			fmt.Fprintf(out, "✗ auth          — %s (%d)\n", apiErr.Code, apiErr.Status)
			return apiErr
		}
		fmt.Fprintf(out, "✗ auth          — %v\n", err)
		return err
	}
	fmt.Fprintf(out, "✓ auth          — credentials accepted\n")

	if cfg.Email != "" {
		fmt.Fprintf(out, "logged in as    %s\n", cfg.Email)
	}
	return nil
}
