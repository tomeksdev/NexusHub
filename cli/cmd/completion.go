package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// completionCmd delegates to Cobra's built-in completion generators
// so users get a consistent story across shells. Source the output,
// don't write it to /etc — the per-distro install paths differ.
var completionCmd = &cobra.Command{
	Use:       "completion [bash|zsh|fish|powershell]",
	Short:     "Generate shell completion script",
	ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
	Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	Long: `Generate a completion script for the chosen shell.

Examples:
  # Bash — load in the current shell:
  source <(nexushub completion bash)

  # Zsh — append to your fpath:
  nexushub completion zsh > "${fpath[1]}/_nexushub"

  # Fish — user completions dir:
  nexushub completion fish > ~/.config/fish/completions/nexushub.fish

  # PowerShell:
  nexushub completion powershell | Out-String | Invoke-Expression`,
	RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return rootCmd.GenBashCompletionV2(os.Stdout, true)
		case "zsh":
			return rootCmd.GenZshCompletion(os.Stdout)
		case "fish":
			return rootCmd.GenFishCompletion(os.Stdout, true)
		case "powershell":
			return rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
		}
		return fmt.Errorf("unknown shell %q", args[0])
	},
}

func init() {
	rootCmd.AddCommand(completionCmd)
}
