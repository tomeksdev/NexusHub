package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/tomeksdev/NexusHub/backend/internal/diag"
)

// DiagHandler exposes operator diagnostics. Read-only; admin-gated by
// the parent group in router.go.
type DiagHandler struct {
	KernelWarnings *diag.KernelWarnings
}

// KernelWarnings returns the active (non-expired) entries newest-first.
// Empty array — never null — when nothing's broken so the frontend can
// branch on .length without a guard.
func (h *DiagHandler) KernelWarningsList(c *gin.Context) {
	out := h.KernelWarnings.List()
	c.JSON(http.StatusOK, gin.H{"items": out})
}
