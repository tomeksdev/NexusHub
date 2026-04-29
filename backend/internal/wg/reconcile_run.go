package wg

import (
	"context"
	"log/slog"
	"net/netip"
	"time"
)

func secondsAsDuration(s int) time.Duration {
	return time.Duration(s) * time.Second
}

// DBInterface is the repository-side view the startup reconciler loads.
// Kept here (in wg/) so internal/repository doesn't need to import wg
// and wg doesn't need to import repository — both parties speak through
// a plain data type.
type DBInterface struct {
	Name       string
	PrivateKey []byte // raw (already decrypted)
	ListenPort int
	Peers      []DBPeer
}

type DBPeer struct {
	PublicKey    string
	PresharedKey []byte // raw (already decrypted); nil when not set
	Endpoint     *string
	AllowedIPs   []netip.Prefix
	AssignedIP   netip.Addr
	Keepalive    *int // seconds
}

// ReconcileStartup is a convenience entry point used from cmd/api/main on
// boot: it converts DB rows to InterfaceSpec values and delegates to
// Reconciler. Errors are logged; nothing here should block startup.
func ReconcileStartup(ctx context.Context, client Client, log *slog.Logger, dbs []DBInterface) {
	if client == nil || len(dbs) == 0 {
		return
	}
	specs := make([]InterfaceSpec, 0, len(dbs))
	for _, d := range dbs {
		spec := InterfaceSpec{
			Name:       d.Name,
			PrivateKey: d.PrivateKey,
			ListenPort: d.ListenPort,
		}
		for _, p := range d.Peers {
			ps := PeerSpec{
				PublicKey:    p.PublicKey,
				PresharedKey: p.PresharedKey,
			}
			if p.Endpoint != nil {
				ps.Endpoint = *p.Endpoint
			}
			// Peers are reachable on their allowed_ips, plus their
			// assigned_ip as a /32 (or /128) so the server can route
			// back even if the operator supplied wider AllowedIPs.
			ps.AllowedIPs = append(ps.AllowedIPs, p.AllowedIPs...)
			ps.AllowedIPs = append(ps.AllowedIPs,
				netip.PrefixFrom(p.AssignedIP, bitsFor(p.AssignedIP)))
			if p.Keepalive != nil {
				ka := secondsAsDuration(*p.Keepalive)
				ps.Keepalive = &ka
			}
			spec.Peers = append(spec.Peers, ps)
		}
		specs = append(specs, spec)
	}
	r := &Reconciler{Client: client, Logger: log}
	_ = r.Reconcile(ctx, specs)
}

func bitsFor(a netip.Addr) int {
	if a.Is4() {
		return 32
	}
	return 128
}
