package handler

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/apierror"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/httppage"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/repository"
)

// AuditHandler exposes read-only admin access to the audit log. Writes
// always go through repository.AuditRepo.Log from other handlers — there
// is no public endpoint to insert synthetic entries.
type AuditHandler struct {
	Audit *repository.AuditRepo
}

type auditResponse struct {
	ID           int64          `json:"id"`
	OccurredAt   time.Time      `json:"occurred_at"`
	ActorUserID  *uuid.UUID     `json:"actor_user_id,omitempty"`
	ActorIP      *string        `json:"actor_ip,omitempty"`
	ActorUA      *string        `json:"actor_ua,omitempty"`
	Action       string         `json:"action"`
	TargetType   string         `json:"target_type"`
	TargetID     *string        `json:"target_id,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	Result       string         `json:"result"`
	ErrorMessage *string        `json:"error_message,omitempty"`
}

func toAuditResponse(a *repository.AuditListItem) auditResponse {
	return auditResponse{
		ID: a.ID, OccurredAt: a.OccurredAt, ActorUserID: a.ActorUserID,
		ActorIP: a.ActorIP, ActorUA: a.ActorUA,
		Action: a.Action, TargetType: a.TargetType, TargetID: a.TargetID,
		Metadata: a.Metadata, Result: a.Result, ErrorMessage: a.ErrorMessage,
	}
}

// List serves GET /api/v1/audit-log. Filters: actor_user_id, action, result,
// since (RFC3339 timestamp). The default sort is occurred_at DESC because
// "what happened most recently" is what an operator almost always wants.
func (h *AuditHandler) List(c *gin.Context) {
	pg := httppage.Parse(c)
	sortField, sortDesc := pg.ResolveSort(repository.AuditSortFields, "occurred_at")
	// Newest-first is the right default for an audit feed. When the client
	// didn't supply a sort direction and we fell back to occurred_at, flip
	// to descending.
	if pg.SortField == "" {
		sortDesc = true
	}

	f := repository.AuditListFilter{}
	if s := c.Query("actor_user_id"); s != "" {
		id, err := uuid.Parse(s)
		if err != nil {
			writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "actor_user_id must be uuid")
			return
		}
		f.ActorUserID = &id
	}
	if s := c.Query("action"); s != "" {
		f.Action = s
	}
	if s := c.Query("result"); s != "" {
		switch s {
		case repository.AuditResultSuccess, repository.AuditResultFailure, repository.AuditResultDenied:
			f.Result = s
		default:
			writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "result must be success|failure|denied")
			return
		}
	}
	if s := c.Query("since"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "since must be RFC3339 timestamp")
			return
		}
		f.Since = &t
	}

	items, total, err := h.Audit.ListPage(c.Request.Context(), f,
		pg.Limit, pg.Offset, sortField, sortDesc)
	if err != nil {
		slog.ErrorContext(c, "list audit", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	out := make([]auditResponse, 0, len(items))
	for i := range items {
		out = append(out, toAuditResponse(&items[i]))
	}
	c.JSON(http.StatusOK, httppage.Wrap(out, total, pg, sortField, sortDesc))
}
