package cmd

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/tomeksdev/NexusHub/cli/internal/client"
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

// ---- create --------------------------------------------------------------

var (
	ruleCreateName        string
	ruleCreateAction      string
	ruleCreateDirection   string
	ruleCreateProtocol    string
	ruleCreateSrc         string
	ruleCreateDst         string
	ruleCreateSrcPortFrom int
	ruleCreateSrcPortTo   int
	ruleCreateDstPortFrom int
	ruleCreateDstPortTo   int
	ruleCreateRatePPS     int
	ruleCreateRateBurst   int
	ruleCreatePriority    int
	ruleCreateInactive    bool
)

var ruleCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an eBPF rule",
	Long: `Create a new eBPF rule. The same flags match the fields the UI
exposes. The server validates enum values (action, direction,
protocol) and port-range bounds; invalid input comes back as a
400 with a human-readable error message.`,
	RunE: runRuleCreate,
}

func init() {
	f := ruleCreateCmd.Flags()
	f.StringVar(&ruleCreateName, "name", "", "rule name (required)")
	f.StringVar(&ruleCreateAction, "action", "", "allow|deny|rate_limit|log (required)")
	f.StringVar(&ruleCreateDirection, "direction", "ingress", "ingress|egress|both")
	f.StringVar(&ruleCreateProtocol, "protocol", "any", "tcp|udp|icmp|any")
	f.StringVar(&ruleCreateSrc, "src", "", "source CIDR")
	f.StringVar(&ruleCreateDst, "dst", "", "destination CIDR")
	f.IntVar(&ruleCreateSrcPortFrom, "src-port-from", 0, "source port range start (tcp/udp only)")
	f.IntVar(&ruleCreateSrcPortTo, "src-port-to", 0, "source port range end")
	f.IntVar(&ruleCreateDstPortFrom, "dst-port-from", 0, "destination port range start")
	f.IntVar(&ruleCreateDstPortTo, "dst-port-to", 0, "destination port range end")
	f.IntVar(&ruleCreateRatePPS, "rate-pps", 0, "packets per second (required when action=rate_limit)")
	f.IntVar(&ruleCreateRateBurst, "rate-burst", 0, "burst capacity (rate_limit only)")
	f.IntVar(&ruleCreatePriority, "priority", 100, "priority 0–1000, higher wins")
	f.BoolVar(&ruleCreateInactive, "inactive", false, "create the rule but leave is_active=false")
	_ = ruleCreateCmd.MarkFlagRequired("name")
	_ = ruleCreateCmd.MarkFlagRequired("action")
	addOutputFlags(ruleCreateCmd)
	ruleCmd.AddCommand(ruleCreateCmd)
}

func runRuleCreate(cmd *cobra.Command, _ []string) error {
	cli, _, err := clientFromFlags(cmd)
	if err != nil {
		return err
	}
	req := client.CreateRuleRequest{
		Name:      ruleCreateName,
		Action:    ruleCreateAction,
		Direction: ruleCreateDirection,
		Protocol:  ruleCreateProtocol,
		SrcCIDR:   ruleCreateSrc,
		DstCIDR:   ruleCreateDst,
	}
	// Port range + rate flags are only meaningful for certain
	// action/protocol combos; server-side validation will reject
	// mismatches, but we pass them through only when set so the
	// request body matches operator intent.
	if ruleCreateSrcPortFrom != 0 || ruleCreateSrcPortTo != 0 {
		from, to := ruleCreateSrcPortFrom, ruleCreateSrcPortTo
		req.SrcPortFrom, req.SrcPortTo = &from, &to
	}
	if ruleCreateDstPortFrom != 0 || ruleCreateDstPortTo != 0 {
		from, to := ruleCreateDstPortFrom, ruleCreateDstPortTo
		req.DstPortFrom, req.DstPortTo = &from, &to
	}
	if ruleCreateRatePPS > 0 {
		pps := ruleCreateRatePPS
		req.RatePPS = &pps
	}
	if ruleCreateRateBurst > 0 {
		burst := ruleCreateRateBurst
		req.RateBurst = &burst
	}
	if ruleCreatePriority != 100 {
		prio := ruleCreatePriority
		req.Priority = &prio
	}
	if ruleCreateInactive {
		active := false
		req.IsActive = &active
	}
	r, err := cli.CreateRule(req)
	if err != nil {
		return err
	}
	if jsonOutput {
		return output.JSON(cmd.OutOrStdout(), r)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "created rule %s (%s %s) prio=%d\n", r.ID, r.Name, r.Action, r.Priority)
	return nil
}

// ---- delete --------------------------------------------------------------

var ruleDeleteCmd = &cobra.Command{
	Use:   "delete <rule-id>",
	Short: "Delete a rule by ID",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, _, err := clientFromFlags(cmd)
		if err != nil {
			return err
		}
		if err := cli.DeleteRule(args[0]); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "deleted rule %s\n", args[0])
		return nil
	},
}

// ---- toggle --------------------------------------------------------------

var ruleToggleCmd = &cobra.Command{
	Use:   "toggle <rule-id>",
	Short: "Flip a rule's is_active flag",
	Long: `Reads the rule's current is_active and PATCHes it to the
opposite value. Useful during incident response: `+"`nexushub rule toggle <id>`"+`
is the fastest way to disable a rule without deleting it.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, _, err := clientFromFlags(cmd)
		if err != nil {
			return err
		}
		current, err := cli.GetRule(args[0])
		if err != nil {
			return err
		}
		flipped := !current.IsActive
		updated, err := cli.UpdateRule(args[0], client.UpdateRuleRequest{IsActive: &flipped})
		if err != nil {
			return err
		}
		state := "off"
		if updated.IsActive {
			state = "on"
		}
		fmt.Fprintf(cmd.OutOrStdout(), "rule %s is now %s\n", updated.ID, state)
		return nil
	},
}

func init() {
	ruleCmd.AddCommand(ruleDeleteCmd)
	ruleCmd.AddCommand(ruleToggleCmd)
}

// Keep strconv import used — list command already uses it for priority.
var _ = strconv.Itoa
