package cmd

import (
	"github.com/spf13/cobra"

	"github.com/tomeksdev/NexusHub/cli/internal/output"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Inspect the audit log",
}

var auditListLimit int

var auditListCmd = &cobra.Command{
	Use:   "list",
	Short: "List recent audit entries, newest first",
	RunE:  runAuditList,
}

func init() {
	auditListCmd.Flags().IntVar(&auditListLimit, "limit", 50, "maximum entries to return")
	addOutputFlags(auditListCmd)
	auditCmd.AddCommand(auditListCmd)
	rootCmd.AddCommand(auditCmd)
}

func runAuditList(cmd *cobra.Command, _ []string) error {
	cli, _, err := clientFromFlags(cmd)
	if err != nil {
		return err
	}
	pg, err := cli.ListAudit(auditListLimit)
	if err != nil {
		return err
	}
	if jsonOutput {
		return output.JSON(cmd.OutOrStdout(), pg)
	}
	rows := make([]output.Row, 0, len(pg.Items))
	for _, e := range pg.Items {
		actor := "—"
		if e.ActorEmail != nil && *e.ActorEmail != "" {
			actor = *e.ActorEmail
		} else if e.ActorIP != nil && *e.ActorIP != "" {
			actor = *e.ActorIP
		}
		rows = append(rows, output.Row{
			e.OccurredAt.Format("2006-01-02 15:04:05"),
			e.Action, e.Result, actor,
			output.Truncate(e.TargetType+"/"+e.TargetID, 40),
		})
	}
	return output.Table(cmd.OutOrStdout(),
		output.Row{"WHEN", "ACTION", "RESULT", "ACTOR", "TARGET"}, rows)
}
