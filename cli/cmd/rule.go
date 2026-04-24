package cmd

import (
	"strconv"

	"github.com/spf13/cobra"

	"github.com/tomeksdev/NexusHub/cli/internal/output"
)

var ruleCmd = &cobra.Command{
	Use:   "rule",
	Short: "Manage eBPF security rules",
}

var ruleListLimit int

var ruleListCmd = &cobra.Command{
	Use:   "list",
	Short: "List eBPF rules ordered by descending priority",
	RunE:  runRuleList,
}

func init() {
	ruleListCmd.Flags().IntVar(&ruleListLimit, "limit", 200, "maximum rules to return")
	addOutputFlags(ruleListCmd)
	ruleCmd.AddCommand(ruleListCmd)
	rootCmd.AddCommand(ruleCmd)
}

func runRuleList(cmd *cobra.Command, _ []string) error {
	cli, _, err := clientFromFlags(cmd)
	if err != nil {
		return err
	}
	pg, err := cli.ListRules(ruleListLimit)
	if err != nil {
		return err
	}
	if jsonOutput {
		return output.JSON(cmd.OutOrStdout(), pg)
	}
	rows := make([]output.Row, 0, len(pg.Items))
	for _, r := range pg.Items {
		active := "off"
		if r.IsActive {
			active = "on"
		}
		src := r.SrcCIDR
		if src == "" {
			src = "*"
		}
		dst := r.DstCIDR
		if dst == "" {
			dst = "*"
		}
		rows = append(rows, output.Row{
			strconv.Itoa(r.Priority),
			output.Truncate(r.Name, 30),
			r.Action, r.Direction, r.Protocol,
			src, dst, active,
		})
	}
	return output.Table(cmd.OutOrStdout(),
		output.Row{"PRIO", "NAME", "ACTION", "DIR", "PROTO", "SRC", "DST", "ACTIVE"}, rows)
}
