package handler

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/tomeksdev/NexusHub/backend/internal/apierror"
	"github.com/tomeksdev/NexusHub/backend/internal/auth"
	"github.com/tomeksdev/NexusHub/backend/internal/httppage"
	"github.com/tomeksdev/NexusHub/backend/internal/repository"
)

// UserHandler exposes admin CRUD on the users table. Self-service
// password change lives on AuthHandler — this surface is for one
// admin acting on another row.
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

func (h *UserHandler) Get(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "invalid id")
		return
	}
	u, err := h.Users.GetByID(c.Request.Context(), id)
	if errors.Is(err, repository.ErrUserNotFound) {
		writeError(c, http.StatusNotFound, apierror.CodeNotFound, "user not found")
		return
	}
	if err != nil {
		slog.ErrorContext(c, "get user", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	c.JSON(http.StatusOK, toUserResponse(u))
}

type createUserRequest struct {
	Email    string `json:"email"    binding:"required,email"`
	Username string `json:"username" binding:"required,min=2,max=64"`
	Password string `json:"password" binding:"required,min=12"`
	Role     string `json:"role"`
}

func (h *UserHandler) Create(c *gin.Context) {
	var req createUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, err.Error())
		return
	}
	role := strings.ToLower(strings.TrimSpace(req.Role))
	if role == "" {
		role = "user"
	}
	if !validRole(role) {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest,
			"role must be super_admin, admin, or user")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		slog.ErrorContext(c, "hash password", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}

	out, err := h.Users.Create(c.Request.Context(), repository.CreateUserParams{
		Email:        strings.ToLower(strings.TrimSpace(req.Email)),
		Username:     strings.TrimSpace(req.Username),
		PasswordHash: hash,
		Role:         role,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			writeError(c, http.StatusConflict, apierror.CodeConflict,
				"email or username already in use")
			return
		}
		slog.ErrorContext(c, "create user", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	c.JSON(http.StatusCreated, toUserResponse(out))
}

type updateUserRequest struct {
	Email    *string `json:"email"`
	Username *string `json:"username"`
	Role     *string `json:"role"`
	IsActive *bool   `json:"is_active"`
}

func (h *UserHandler) Update(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "invalid id")
		return
	}
	var req updateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, err.Error())
		return
	}
	if req.Role != nil {
		v := strings.ToLower(strings.TrimSpace(*req.Role))
		if !validRole(v) {
			writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest,
				"role must be super_admin, admin, or user")
			return
		}
		req.Role = &v
	}
	if req.Email != nil {
		v := strings.ToLower(strings.TrimSpace(*req.Email))
		req.Email = &v
	}

	out, err := h.Users.Update(c.Request.Context(), id, repository.UpdateUserParams{
		Email: req.Email, Username: req.Username, Role: req.Role, IsActive: req.IsActive,
	})
	if errors.Is(err, repository.ErrUserNotFound) {
		writeError(c, http.StatusNotFound, apierror.CodeNotFound, "user not found")
		return
	}
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			writeError(c, http.StatusConflict, apierror.CodeConflict,
				"email or username already in use")
			return
		}
		slog.ErrorContext(c, "update user", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	c.JSON(http.StatusOK, toUserResponse(out))
}

type setPasswordRequest struct {
	Password string `json:"password" binding:"required,min=12"`
}

// SetPassword is the admin reset endpoint. The new password takes
// effect immediately — there is no "must change at next login" flag in
// the schema today, so document the reset in audit log and move on.
// Self-service password change still goes through /auth/password.
func (h *UserHandler) SetPassword(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "invalid id")
		return
	}
	var req setPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, err.Error())
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		slog.ErrorContext(c, "hash password", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	if err := h.Users.AdminSetPassword(c.Request.Context(), id, hash); err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			writeError(c, http.StatusNotFound, apierror.CodeNotFound, "user not found")
			return
		}
		slog.ErrorContext(c, "admin set password", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	c.Status(http.StatusNoContent)
}

// Delete soft-deletes by default (is_active=false). ?force=true does a
// hard delete; wg_peers.owner_user_id is ON DELETE SET NULL so peers
// survive but lose their owner link. Sessions cascade.
func (h *UserHandler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "invalid id")
		return
	}
	force := c.Query("force") == "true"
	ctx := c.Request.Context()
	if force {
		err = h.Users.HardDelete(ctx, id)
	} else {
		err = h.Users.SoftDelete(ctx, id)
	}
	if errors.Is(err, repository.ErrUserNotFound) {
		writeError(c, http.StatusNotFound, apierror.CodeNotFound, "user not found")
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "delete user", "err", err, "force", force)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	c.Status(http.StatusNoContent)
}

func validRole(r string) bool {
	return r == "super_admin" || r == "admin" || r == "user"
}
