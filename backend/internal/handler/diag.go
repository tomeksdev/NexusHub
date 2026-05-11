package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/tomeksdev/NexusHub/backend/internal/diag"
)

// EBPFInventory is the read-side seam between the eBPF stack
// (cmd/api) and the diagnostics handler. Lets the handler render
// "what's attached" without pulling cilium/ebpf into its compile
// graph.
type EBPFInventory interface {
	AttachedPrograms() []diag.EBPFAttachment
	PinPath() string
}

// DiagHandler exposes operator diagnostics. Read-only; admin-gated by
// the parent group in router.go.
type DiagHandler struct {
	KernelWarnings *diag.KernelWarnings
	// EBPF is the inventory for the /diag/ebpf endpoint. Nil ⇒ the
	// endpoint reports an empty inventory rather than 500ing, so a
	// dev environment without the stack still serves the page.
	EBPF EBPFInventory
}

// KernelWarningsList returns the active (non-expired) entries
// newest-first. Empty array — never null — when nothing's broken
// so the frontend can branch on .length without a guard.
func (h *DiagHandler) KernelWarningsList(c *gin.Context) {
	out := h.KernelWarnings.List()
	c.JSON(http.StatusOK, gin.H{"items": out})
}

// EBPFState describes the data plane attachment from the API's
// point of view. The operator can cross-check this against
// `bpftool prog show` and `bpftool net` on the host — a match
// means the API and kernel agree on what's loaded.
type ebpfStateResponse struct {
	Programs []diag.EBPFAttachment `json:"programs"`
	PinPath  string                `json:"pin_path"`
}

// EBPFState returns the snapshot of attached programs + the
// bpffs pin path the loader uses. Round-9 observability: lets the
// Support page tell at a glance whether the data plane is up and
// which interfaces it's bound to, without leaving the browser.
func (h *DiagHandler) EBPFState(c *gin.Context) {
	resp := ebpfStateResponse{Programs: []diag.EBPFAttachment{}}
	if h.EBPF != nil {
		if p := h.EBPF.AttachedPrograms(); p != nil {
			resp.Programs = p
		}
		resp.PinPath = h.EBPF.PinPath()
	}
	c.JSON(http.StatusOK, resp)
}
