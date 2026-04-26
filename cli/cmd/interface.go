package cmd

import (
	"strconv"

	"github.com/spf13/cobra"

	"github.com/tomeksdev/NexusHub/cli/internal/output"
)

var interfaceCmd = &cobra.Command{
	Use:     "interface",
	Aliases: []string{"iface"},
	Short:   "Inspect WireGuard interfaces",
}

var ifaceListLimit int

var interfaceListCmd = &cobra.Command{
	Use:   "list",
	Short: "List configured WireGuard interfaces",
	RunE:  runInterfaceList,
}

func init() {
	interfaceListCmd.Flags().IntVar(&ifaceListLimit, "limit", 50, "maximum interfaces to return")
	addOutputFlags(interfaceListCmd)
	interfaceCmd.AddCommand(interfaceListCmd)
	rootCmd.AddCommand(interfaceCmd)
}

func runInterfaceList(cmd *cobra.Command, _ []string) error {
	cli, _, err := clientFromFlags(cmd)
	if err != nil {
		return err
	}
	pg, err := cli.ListInterfaces(ifaceListLimit)
	if err != nil {
		return err
	}
	if jsonOutput {
		return output.JSON(cmd.OutOrStdout(), pg)
	}
	rows := make([]output.Row, 0, len(pg.Items))
	for _, i := range pg.Items {
		active := "off"
		if i.IsActive {
			active = "on"
		}
		rows = append(rows, output.Row{
			output.Truncate(i.ID, 8), i.Name, i.Address,
			strconv.Itoa(i.ListenPort), active,
		})
	}
	return output.Table(cmd.OutOrStdout(),
		output.Row{"ID", "NAME", "ADDRESS", "PORT", "ACTIVE"}, rows)
}
