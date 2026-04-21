package handler

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/tomeksdev/NexusHub/backend/internal/apierror"
	"github.com/tomeksdev/NexusHub/backend/internal/auth"
	"github.com/tomeksdev/NexusHub/backend/internal/middleware"
	"github.com/tomeksdev/NexusHub/backend/internal/repository"
)

// AuthHandler owns login, refresh, logout, and password-change endpoints.
type AuthHandler struct {
	Users      *repository.UserRepo
	Sessions   *repository.SessionRepo
	Audit      *repository.AuditRepo
	JWT        *auth.JWTIssuer
	RefreshTTL time.Duration
}

type loginRequest struct {
	Email    string `json:"email"    binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type tokenResponse struct {
	AccessToken     string    `json:"access_token"`
	RefreshToken    string    `json:"refresh_token"`
	AccessExpiresAt time.Time `json:"access_expires_at"`
	Role            string    `json:"role"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type logoutRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type passwordChangeRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password"     binding:"required,min=12"`
}

// Login authenticates email+password and issues the first access+refresh
// pair. Uses constant-ish responses for unknown email vs. bad password to
// defeat user enumeration.
func (h *AuthHandler) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, err.Error())
		return
	}

	ctx := c.Request.Context()
	creds, err := h.Users.GetCredentialsByEmail(ctx, req.Email)
	if errors.Is(err, repository.ErrUserNotFound) {
		h.Audit.Log(ctx, repository.AuditEntry{
			ActorIP: clientIP(c), ActorUA: c.Request.UserAgent(),
			Action: "auth.login", TargetType: "user", TargetID: req.Email,
			Result: repository.AuditResultFailure, ErrorMessage: "unknown email",
		})
		writeError(c, http.StatusUnauthorized, apierror.CodeInvalidCredentials, "invalid credentials")
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "login lookup", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}

	if !creds.IsActive {
		h.auditLoginFailure(ctx, c, creds.ID, "account disabled")
		writeError(c, http.StatusForbidden, apierror.CodeAccountDisabled, "account disabled")
		return
	}
	if creds.LockedUntil != nil && creds.LockedUntil.After(time.Now()) {
		h.auditLoginFailure(ctx, c, creds.ID, "account locked")
		writeError(c, http.StatusForbidden, apierror.CodeAccountLocked, "account locked")
		return
	}

	ok, err := auth.VerifyPassword(req.Password, creds.PasswordHash)
	if err != nil || !ok {
		if markErr := h.Users.MarkLoginFailure(ctx, creds.ID); markErr != nil {
			slog.ErrorContext(ctx, "mark login failure", "err", markErr)
		}
		h.auditLoginFailure(ctx, c, creds.ID, "bad password")
		writeError(c, http.StatusUnauthorized, apierror.CodeInvalidCredentials, "invalid credentials")
		return
	}

	resp, err := h.issueSession(ctx, c, creds.ID, creds.Role)
	if err != nil {
		slog.ErrorContext(ctx, "issue session", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}

	if err := h.Users.MarkLoginSuccess(ctx, creds.ID); err != nil {
		slog.ErrorContext(ctx, "mark login success", "err", err)
	}
	h.Audit.Log(ctx, repository.AuditEntry{
		ActorUserID: &creds.ID, ActorIP: clientIP(c), ActorUA: c.Request.UserAgent(),
		Action: "auth.login", TargetType: "user", TargetID: creds.ID.String(),
		Result: repository.AuditResultSuccess,
	})
	c.JSON(http.StatusOK, resp)
}

// Refresh rotates the refresh token and issues a new access token.
func (h *AuthHandler) Refresh(c *gin.Context) {
	var req refreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, err.Error())
		return
	}

	ctx := c.Request.Context()
	presented, err := auth.HashRefreshToken(req.RefreshToken)
	if err != nil {
		writeError(c, http.StatusUnauthorized, apierror.CodeRefreshInvalid, "invalid refresh token")
		return
	}
	newPlain, newHash, err := auth.NewRefreshToken()
	if err != nil {
		slog.ErrorContext(ctx, "new refresh", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}

	userID, sessionID, role, result, err := h.Sessions.RotateRefreshToken(ctx, presented, newHash, h.RefreshTTL)
	switch {
	case errors.Is(err, repository.ErrRefreshTokenReused):
		h.Audit.Log(ctx, repository.AuditEntry{
			ActorIP: clientIP(c), ActorUA: c.Request.UserAgent(),
			Action: "auth.refresh", TargetType: "session",
			Result: repository.AuditResultDenied, ErrorMessage: "refresh reuse detected",
		})
		writeError(c, http.StatusUnauthorized, apierror.CodeRefreshReused, "refresh token reused; session revoked")
		return
	case errors.Is(err, repository.ErrRefreshTokenInvalid):
		writeError(c, http.StatusUnauthorized, apierror.CodeRefreshInvalid, "invalid refresh token")
		return
	case err != nil:
		slog.ErrorContext(ctx, "rotate refresh", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}

	access, accessExp, err := h.JWT.IssueAccess(userID, sessionID, role)
	if err != nil {
		slog.ErrorContext(ctx, "issue access", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}

	h.Audit.Log(ctx, repository.AuditEntry{
		ActorUserID: &userID, ActorIP: clientIP(c), ActorUA: c.Request.UserAgent(),
		Action: "auth.refresh", TargetType: "session", TargetID: sessionID.String(),
		Result: repository.AuditResultSuccess,
	})
	_ = result
	c.JSON(http.StatusOK, tokenResponse{
		AccessToken:     access,
		RefreshToken:    newPlain,
		AccessExpiresAt: accessExp,
		Role:            role,
	})
}

// Logout revokes the session behind the presented refresh token. We do not
// require an access token here so a client that has already lost its access
// token can still revoke.
func (h *AuthHandler) Logout(c *gin.Context) {
	var req logoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, err.Error())
		return
	}

	ctx := c.Request.Context()
	presented, err := auth.HashRefreshToken(req.RefreshToken)
	if err != nil {
		// Malformed token → treat as already-logged-out to keep the endpoint
		// idempotent and opaque.
		c.Status(http.StatusNoContent)
		return
	}

	sessionID, userID, err := h.Sessions.LookupByRefreshHash(ctx, presented)
	if err != nil {
		c.Status(http.StatusNoContent)
		return
	}

	if _, err := h.Sessions.RevokeSession(ctx, sessionID); err != nil {
		slog.ErrorContext(ctx, "revoke session", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}

	h.Audit.Log(ctx, repository.AuditEntry{
		ActorUserID: &userID, ActorIP: clientIP(c), ActorUA: c.Request.UserAgent(),
		Action: "auth.logout", TargetType: "session", TargetID: sessionID.String(),
		Result: repository.AuditResultSuccess,
	})
	c.Status(http.StatusNoContent)
}

// ChangePassword verifies the current password and rotates the hash.
// Revokes every session for the user — all active clients must re-login.
// Requires RequireAuth.
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	var req passwordChangeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, err.Error())
		return
	}

	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		writeError(c, http.StatusUnauthorized, apierror.CodeUnauthorized, "unauthenticated")
		return
	}

	ctx := c.Request.Context()
	currentHash, err := h.Users.GetPasswordHash(ctx, principal.UserID)
	if err != nil {
		writeError(c, http.StatusUnauthorized, apierror.CodeUnauthorized, "unauthenticated")
		return
	}

	matches, err := auth.VerifyPassword(req.CurrentPassword, currentHash)
	if err != nil || !matches {
		writeError(c, http.StatusUnauthorized, apierror.CodeInvalidCredentials, "current password incorrect")
		return
	}

	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		slog.ErrorContext(ctx, "hash password", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	if err := h.Users.UpdatePassword(ctx, principal.UserID, newHash); err != nil {
		slog.ErrorContext(ctx, "update password", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	if err := h.Sessions.RevokeAllForUser(ctx, principal.UserID); err != nil {
		slog.ErrorContext(ctx, "revoke sessions", "err", err)
	}
	h.Audit.Log(ctx, repository.AuditEntry{
		ActorUserID: &principal.UserID, ActorIP: clientIP(c), ActorUA: c.Request.UserAgent(),
		Action: "auth.password_change", TargetType: "user", TargetID: principal.UserID.String(),
		Result: repository.AuditResultSuccess,
	})
	c.Status(http.StatusNoContent)
}

func (h *AuthHandler) issueSession(ctx context.Context, c *gin.Context, userID uuid.UUID, role string) (tokenResponse, error) {
	refreshPlain, refreshHash, err := auth.NewRefreshToken()
	if err != nil {
		return tokenResponse{}, err
	}
	issued, err := h.Sessions.CreateSession(ctx, userID, refreshHash, h.RefreshTTL, clientIP(c), c.Request.UserAgent())
	if err != nil {
		return tokenResponse{}, err
	}
	access, accessExp, err := h.JWT.IssueAccess(userID, issued.SessionID, role)
	if err != nil {
		return tokenResponse{}, err
	}
	return tokenResponse{
		AccessToken:     access,
		RefreshToken:    refreshPlain,
		AccessExpiresAt: accessExp,
		Role:            role,
	}, nil
}

func (h *AuthHandler) auditLoginFailure(ctx context.Context, c *gin.Context, userID uuid.UUID, reason string) {
	h.Audit.Log(ctx, repository.AuditEntry{
		ActorUserID: &userID, ActorIP: clientIP(c), ActorUA: c.Request.UserAgent(),
		Action: "auth.login", TargetType: "user", TargetID: userID.String(),
		Result: repository.AuditResultFailure, ErrorMessage: reason,
	})
}

func clientIP(c *gin.Context) net.IP {
	ip := net.ParseIP(c.ClientIP())
	return ip
}
