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

// UserHandler exposes admin-only read access to the users table. Writes
// (create/role change/disable) live behind their own audit-heavy endpoints
// which haven't been scoped yet — this handler intentionally stops at List.
type UserHandler struct {
	Users *repository.UserRepo
}

type userResponse struct {
	ID           uuid.UUID  `json:"id"`
	Email        string     `json:"email"`
	Username     string     `json:"username"`
	Role         string     `json:"role"`
	IsActive     bool       `json:"is_active"`
	TOTPEnabled  bool       `json:"totp_enabled"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
	FailedLogins int        `json:"failed_logins"`
	LockedUntil  *time.Time `json:"locked_until,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

func toUserResponse(u *repository.UserListItem) userResponse {
	return userResponse{
		ID: u.ID, Email: u.Email, Username: u.Username, Role: u.Role,
		IsActive: u.IsActive, TOTPEnabled: u.TOTPEnabled,
		LastLoginAt: u.LastLoginAt, FailedLogins: u.FailedLogins,
		LockedUntil: u.LockedUntil,
		CreatedAt:   u.CreatedAt, UpdatedAt: u.UpdatedAt,
	}
}

func (h *UserHandler) List(c *gin.Context) {
	pg := httppage.Parse(c)
	sortField, sortDesc := pg.ResolveSort(repository.UserSortFields, "email")
	items, total, err := h.Users.ListPage(c.Request.Context(),
		pg.Limit, pg.Offset, sortField, sortDesc)
	if err != nil {
		slog.ErrorContext(c, "list users", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	out := make([]userResponse, 0, len(items))
	for i := range items {
		out = append(out, toUserResponse(&items[i]))
	}
	c.JSON(http.StatusOK, httppage.Wrap(out, total, pg, sortField, sortDesc))
}
