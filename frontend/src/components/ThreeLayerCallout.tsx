// ThreeLayerCallout explains the three independent layers that
// determine what a peer can actually do on the network. Rendered
// above the network fields in PeerCreateModal + PeerEditModal so an
// operator setting one field knows what the others control.
//
// The three layers are independent on purpose: a client can write
// AllowedIPs=0.0.0.0/0 in its local .conf, but that's just routing
// intent — the kernel WG module still rejects packets whose source
// isn't in the server's per-peer AllowedIPs, and the eBPF rule engine
// still drops anything that doesn't match an allow rule.
export function ThreeLayerCallout() {
  return (
    <div
      className="rounded-md p-3 text-xs"
      style={{
        background: "rgba(255,255,255,0.04)",
        border: "1px solid var(--color-line)",
      }}
    >
      <strong className="text-sm">Three independent layers</strong>
      <ul className="mt-1.5 space-y-1 list-none">
        <li>
          <span className="text-muted">Client routed networks</span> — what the
          client's .conf tells it to route. Routing intent only; never
          authorization.
        </li>
        <li>
          <span className="text-muted">Server-side accepted IPs</span> — the WG
          kernel module rejects packets from this peer whose source isn't in
          this list. Validation only; never authorization.
        </li>
        <li>
          <span className="text-muted">Access rules (eBPF)</span> — the actual
          authorization layer. A peer can only reach what an allow rule lets
          through, regardless of what the two layers above are set to.
        </li>
      </ul>
    </div>
  );
}
