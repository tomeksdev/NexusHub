package cmd

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/tomeksdev/NexusHub/cli/internal/client"
	"github.com/tomeksdev/NexusHub/cli/internal/output"
)

var peerCmd = &cobra.Command{
	Use:   "peer",
	Short: "Manage WireGuard peers",
}

var (
	peerListIface string
	peerListLimit int
)

var peerListCmd = &cobra.Command{
	Use:   "list",
	Short: "List peers on an interface",
	RunE:  runPeerList,
}

func init() {
	peerListCmd.Flags().StringVar(&peerListIface, "interface", "", "interface ID to scope the list; defaults to the first interface")
	peerListCmd.Flags().IntVar(&peerListLimit, "limit", 100, "maximum peers to return")
	addOutputFlags(peerListCmd)
	peerCmd.AddCommand(peerListCmd)
	rootCmd.AddCommand(peerCmd)
}

func runPeerList(cmd *cobra.Command, _ []string) error {
	cli, _, err := clientFromFlags(cmd)
	if err != nil {
		return err
	}

	// The /peers endpoint requires interface_id. Auto-resolve to the
	// first interface when the flag is absent — matches the frontend's
	// default behaviour and keeps `nexushub peer list` usable on
	// single-interface deployments without extra flags.
	ifaceID := peerListIface
	if ifaceID == "" {
		ifaces, err := cli.ListInterfaces(1)
		if err != nil {
			return fmt.Errorf("resolve default interface: %w", err)
		}
		if len(ifaces.Items) == 0 {
			return fmt.Errorf("no interfaces configured; pass --interface once you create one")
		}
		ifaceID = ifaces.Items[0].ID
	}

	pg, err := cli.ListPeers(ifaceID, peerListLimit)
	if err != nil {
		return err
	}
	if jsonOutput {
		return output.JSON(cmd.OutOrStdout(), pg)
	}
	rows := make([]output.Row, 0, len(pg.Items))
	for _, p := range pg.Items {
		hs := "—"
		if p.LastHandshake != nil && *p.LastHandshake != "" {
			hs = *p.LastHandshake
		}
		rows = append(rows, output.Row{
			output.Truncate(p.ID, 8),
			p.Name,
			p.AssignedIP,
			p.Status,
			hs,
			strconv.FormatInt(p.RxBytes, 10),
			strconv.FormatInt(p.TxBytes, 10),
		})
	}
	return output.Table(cmd.OutOrStdout(),
		output.Row{"ID", "NAME", "IP", "STATUS", "LAST HANDSHAKE", "RX", "TX"}, rows)
}

// Satisfy the import (client is used above via the shared helper).
var _ = client.Peer{}
