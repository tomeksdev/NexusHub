package cmd

import (
	"fmt"
	"strconv"
	"strings"

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

// ---- create --------------------------------------------------------------

var (
	peerCreateName        string
	peerCreateIface       string
	peerCreateDescription string
	peerCreateAssignedIP  string
	peerCreateAllowedIPs  string
	peerCreateEndpoint    string
	peerCreateKeepalive   int
)

var peerCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a peer (server generates the keypair)",
	Long: `Create a new peer on an interface. The server generates the key
pair and, when --ip is omitted, auto-allocates a host address from
the interface's CIDR. Prints the created peer record, including the
fields needed to configure the client side.`,
	RunE: runPeerCreate,
}

func init() {
	peerCreateCmd.Flags().StringVar(&peerCreateName, "name", "", "peer name (required)")
	peerCreateCmd.Flags().StringVar(&peerCreateIface, "interface", "", "interface ID (defaults to the first interface)")
	peerCreateCmd.Flags().StringVar(&peerCreateDescription, "description", "", "optional description")
	peerCreateCmd.Flags().StringVar(&peerCreateAssignedIP, "ip", "", "assigned IP; auto-allocated when omitted")
	peerCreateCmd.Flags().StringVar(&peerCreateAllowedIPs, "allowed-ips", "", "comma-separated AllowedIPs CIDRs")
	peerCreateCmd.Flags().StringVar(&peerCreateEndpoint, "endpoint", "", "override the peer's endpoint (host:port)")
	peerCreateCmd.Flags().IntVar(&peerCreateKeepalive, "keepalive", 0, "persistent-keepalive interval in seconds")
	_ = peerCreateCmd.MarkFlagRequired("name")
	addOutputFlags(peerCreateCmd)
	peerCmd.AddCommand(peerCreateCmd)
}

func runPeerCreate(cmd *cobra.Command, _ []string) error {
	cli, _, err := clientFromFlags(cmd)
	if err != nil {
		return err
	}
	ifaceID := peerCreateIface
	if ifaceID == "" {
		ifaces, err := cli.ListInterfaces(1)
		if err != nil {
			return fmt.Errorf("resolve default interface: %w", err)
		}
		if len(ifaces.Items) == 0 {
			return fmt.Errorf("no interfaces configured; pass --interface")
		}
		ifaceID = ifaces.Items[0].ID
	}
	req := client.CreatePeerRequest{
		InterfaceID: ifaceID,
		Name:        peerCreateName,
		Description: peerCreateDescription,
		AssignedIP:  peerCreateAssignedIP,
		Endpoint:    peerCreateEndpoint,
	}
	if peerCreateKeepalive > 0 {
		req.PersistentKeepAlive = peerCreateKeepalive
	}
	if s := strings.TrimSpace(peerCreateAllowedIPs); s != "" {
		parts := strings.Split(s, ",")
		req.AllowedIPs = make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				req.AllowedIPs = append(req.AllowedIPs, p)
			}
		}
	}
	p, err := cli.CreatePeer(req)
	if err != nil {
		return err
	}
	if jsonOutput {
		return output.JSON(cmd.OutOrStdout(), p)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "created peer %s (%s) %s\n", p.ID, p.Name, p.AssignedIP)
	return nil
}

// ---- delete --------------------------------------------------------------

var peerDeleteCmd = &cobra.Command{
	Use:   "delete <peer-id>",
	Short: "Delete a peer by ID",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, _, err := clientFromFlags(cmd)
		if err != nil {
			return err
		}
		if err := cli.DeletePeer(args[0]); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "deleted peer %s\n", args[0])
		return nil
	},
}

func init() {
	peerCmd.AddCommand(peerDeleteCmd)
}
