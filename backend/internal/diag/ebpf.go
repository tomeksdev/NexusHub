package diag

import "time"

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

// EBPFLoaderStatus is the operator-facing snapshot of whether the
// kernel datapath actually loaded. Surfaced under
// `/api/v1/diag/ebpf.loader` so the Support page and the Rules
// page can banner the degraded state instead of letting the per-
// rule "NOT LOADED" badge accumulate without explanation. (#86)
//
// Loaded=true means the program is in the kernel and Syncer.Has
// returns true for rules that should be live; Loaded=false means
// the API is running with a NoopSyncer and no rule enforces,
// regardless of what the rules page shows.
//
// Error is the last init error verbatim. Empty when Loaded=true.
// Frontend surfaces it directly so the operator doesn't have to
// scrape journalctl.
//
// MissingFeatures + PermissionDenied are the two structured
// reasons load might fail that the operator can act on without
// reading the raw error: kernel doesn't support a feature the
// loader requires (upgrade the kernel) vs. the process lacks
// CAP_BPF / CAP_NET_ADMIN (fix the container / unit).
type EBPFLoaderStatus struct {
	Loaded           bool      `json:"loaded"`
	Error            string    `json:"error,omitempty"`
	CapabilitiesOK   bool      `json:"capabilities_ok"`
	MissingFeatures  []string  `json:"missing_features"`
	PermissionDenied bool      `json:"permission_denied"`
	LastAttemptAt    time.Time `json:"last_attempt_at"`
}
