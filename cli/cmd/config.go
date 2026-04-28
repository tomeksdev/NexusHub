package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/tomeksdev/NexusHub/cli/internal/client"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Export or import deployment configuration",
}

// ConfigSnapshot is the on-disk shape of `config export`. It's a
// point-in-time dump of the resources the CLI can read, intended
// for backup + diffing + GitOps workflows. Users and audit entries
// are intentionally out of scope — the first because it'd include
// hashed credentials, the second because it's append-only event
// data, not configuration.
type ConfigSnapshot struct {
	ExportedAt time.Time          `json:"exported_at"`
	Server     string             `json:"server"`
	Interfaces []client.Interface `json:"interfaces"`
	Peers      []client.Peer      `json:"peers"`
	Rules      []client.Rule      `json:"rules"`
}

var configExportFile string

var configExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Dump the current deployment config as JSON",
	Long: `Fetches every interface, peer, and rule the current
credentials can see and writes a single JSON document. Use --file
to write to a path; omitting it prints to stdout.

The export excludes users (which carry credential material) and
audit entries (which are event data, not configuration).`,
	RunE: runConfigExport,
}

func init() {
	configExportCmd.Flags().StringVarP(&configExportFile, "file", "o", "", "write to this file instead of stdout")
	configCmd.AddCommand(configExportCmd)
	rootCmd.AddCommand(configCmd)
}

func runConfigExport(cmd *cobra.Command, _ []string) error {
	cli, _, err := clientFromFlags(cmd)
	if err != nil {
		return err
	}

	ifaces, err := cli.ListInterfaces(1000)
	if err != nil {
		return fmt.Errorf("list interfaces: %w", err)
	}
	rules, err := cli.ListRules(10_000)
	if err != nil {
		return fmt.Errorf("list rules: %w", err)
	}
	// Peers fan out per interface. O(interfaces) API calls; fine at
	// the hundreds-of-interfaces scale this CLI targets.
	peers := make([]client.Peer, 0, 256)
	for _, iface := range ifaces.Items {
		pg, err := cli.ListPeers(iface.ID, 10_000)
		if err != nil {
			return fmt.Errorf("list peers for %s: %w", iface.Name, err)
		}
		peers = append(peers, pg.Items...)
	}

	snap := ConfigSnapshot{
		ExportedAt: time.Now().UTC(),
		Server:     cli.BaseURL(),
		Interfaces: ifaces.Items,
		Peers:      peers,
		Rules:      rules.Items,
	}
	raw, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}
	raw = append(raw, '\n')

	if configExportFile == "" {
		_, err := cmd.OutOrStdout().Write(raw)
		return err
	}
	// 0o600 so the file (which may carry peer endpoints + CIDRs
	// useful for network reconnaissance) isn't world-readable by
	// default. Operators who need group-readability can chmod
	// after the fact.
	if err := os.WriteFile(configExportFile, raw, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "wrote %d bytes to %s\n", len(raw), configExportFile)
	return nil
}
