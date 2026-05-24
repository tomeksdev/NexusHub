package diag

// EBPFAttachment is one row in the /diag/ebpf inventory. Lives in
// the dependency-free diag package so both the handler layer and
// the cmd-package wiring can refer to it without dragging cilium
// /ebpf into the handler compile graph.
//
// Hook is one of "ingress" / "egress" / "xdp". ProgID is the
// kernel-assigned program identifier; 0 means the loader didn't
// publish one (uncommon — usually a degraded state).
type EBPFAttachment struct {
	Iface   string `json:"iface"`
	Hook    string `json:"hook"`
	Program string `json:"program"`
	ProgID  uint32 `json:"prog_id"`
}
