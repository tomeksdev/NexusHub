package cmd

import (
	"github.com/spf13/cobra"

	"github.com/tomeksdev/NexusHub/cli/internal/output"
)

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Inspect NexusHub users (admin only)",
}

var userListLimit int

var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List users. Requires admin or super_admin role on the logged-in account.",
	RunE:  runUserList,
}

func init() {
	userListCmd.Flags().IntVar(&userListLimit, "limit", 100, "maximum users to return")
	addOutputFlags(userListCmd)
	userCmd.AddCommand(userListCmd)
	rootCmd.AddCommand(userCmd)
}

func runUserList(cmd *cobra.Command, _ []string) error {
	cli, _, err := clientFromFlags(cmd)
	if err != nil {
		return err
	}
	pg, err := cli.ListUsers(userListLimit)
	if err != nil {
		return err
	}
	if jsonOutput {
		return output.JSON(cmd.OutOrStdout(), pg)
	}
	rows := make([]output.Row, 0, len(pg.Items))
	for _, u := range pg.Items {
		status := "active"
		if !u.IsActive {
			status = "disabled"
		}
		totp := "off"
		if u.TOTPEnabled {
			totp = "on"
		}
		last := "—"
		if u.LastLoginAt != nil {
			last = *u.LastLoginAt
		}
		rows = append(rows, output.Row{u.Email, u.Username, u.Role, status, totp, last})
	}
	return output.Table(cmd.OutOrStdout(),
		output.Row{"EMAIL", "USERNAME", "ROLE", "STATUS", "2FA", "LAST LOGIN"}, rows)
}
