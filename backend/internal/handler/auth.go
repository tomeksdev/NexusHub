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
	"github.com/tomeksdev/NexusHub/backend/internal/crypto"
	"github.com/tomeksdev/NexusHub/backend/internal/middleware"
	"github.com/tomeksdev/NexusHub/backend/internal/repository"
)

// AuthHandler owns login, refresh, logout, and password-change endpoints
// plus the TOTP enrollment / verify / disable flow. AEAD decrypts the
// TOTP secret stored on the user row; the same instance that encrypts
// peer private keys is reused so there's one master key to rotate.
type AuthHandler struct {
	Users      *repository.UserRepo
	Sessions   *repository.SessionRepo
	Audit      *repository.AuditRepo
	JWT        *auth.JWTIssuer
	AEAD       *crypto.AEAD
	RefreshTTL time.Duration
}

// totpSecretAD is the additional-data constant passed to AEAD for
// TOTP ciphertexts. Distinct from the peer-key AD so a ciphertext
// copied between columns can't be decrypted in the wrong context.
var totpSecretAD = []byte("users.totp_secret")

type loginRequest struct {
	Email    string `json:"email"    binding:"required,email"`
	Password string `json:"password" binding:"required"`
	// TOTPCode is required when the user has 2FA enabled. Omitting it
	// on a 2FA-enabled account yields CodeTOTPRequired, which the
	// frontend uses as a signal to collect the code and retry.
	TOTPCode string `json:"totp_code"`
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

	// Second factor gate. Password was correct; if the user enrolled
	// TOTP we require a valid code before issuing tokens.
	//
	// We distinguish "code missing" (CodeTOTPRequired — benign, the
	// client hasn't collected it yet) from "code wrong" (Code
	// TOTPInvalid — tick the failure counter, same lockout path as
	// a bad password). This matches how most 2FA flows segment the
	// UX vs. the security signals.
	if creds.TOTPEnabled {
		if req.TOTPCode == "" {
			writeError(c, http.StatusUnauthorized, apierror.CodeTOTPRequired, "totp code required")
			return
		}
		secret, derr := h.AEAD.Open(creds.TOTPSecretCipher, totpSecretAD)
		if derr != nil {
			slog.ErrorContext(ctx, "decrypt totp secret", "err", derr, "user_id", creds.ID)
			writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
			return
		}
		if !auth.ValidateTOTP(string(secret), req.TOTPCode) {
			if markErr := h.Users.MarkLoginFailure(ctx, creds.ID); markErr != nil {
				slog.ErrorContext(ctx, "mark login failure", "err", markErr)
			}
			h.auditLoginFailure(ctx, c, creds.ID, "bad totp")
			writeError(c, http.StatusUnauthorized, apierror.CodeTOTPInvalid, "invalid totp code")
			return
		}
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

// ----- TOTP ----------------------------------------------------------------

type totpEnrollResponse struct {
	// Secret is the base32-encoded shared secret, for users who enter
	// it into an authenticator app manually. Never displayed after
	// verification succeeds.
	Secret string `json:"secret"`
	// OtpauthURI is the otpauth:// URL the frontend renders as a QR.
	OtpauthURI string `json:"otpauth_uri"`
	// AccountName is the label that appears in the authenticator app.
	AccountName string `json:"account_name"`
}

type totpVerifyRequest struct {
	Code string `json:"code" binding:"required,len=6"`
}

type totpDisableRequest struct {
	Password string `json:"password" binding:"required"`
	Code     string `json:"code"     binding:"required,len=6"`
}

// EnrollTOTP generates a fresh secret and stores it in the pending
// state (secret set, enabled=false). The client renders the QR, the
// user scans it, and the enrollment completes on the first successful
// VerifyTOTP call. Calling Enroll again before Verify overwrites the
// pending secret — useful when a user abandons setup mid-flow.
func (h *AuthHandler) EnrollTOTP(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		writeError(c, http.StatusUnauthorized, apierror.CodeUnauthorized, "unauthenticated")
		return
	}
	ctx := c.Request.Context()

	// Use the user's email as the authenticator-app label so the
	// same account shows up consistently across devices.
	email, err := h.Users.GetEmail(ctx, principal.UserID)
	if err != nil {
		slog.ErrorContext(ctx, "totp enroll: get email", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	enrollment, err := auth.GenerateTOTP(email)
	if err != nil {
		slog.ErrorContext(ctx, "totp enroll: generate", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	cipher, err := h.AEAD.Seal([]byte(enrollment.Secret), totpSecretAD)
	if err != nil {
		slog.ErrorContext(ctx, "totp enroll: seal", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	if err := h.Users.SetTOTPPending(ctx, principal.UserID, cipher); err != nil {
		slog.ErrorContext(ctx, "totp enroll: persist", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	h.Audit.Log(ctx, repository.AuditEntry{
		ActorUserID: &principal.UserID, ActorIP: clientIP(c), ActorUA: c.Request.UserAgent(),
		Action: "auth.totp_enroll", TargetType: "user", TargetID: principal.UserID.String(),
		Result: repository.AuditResultSuccess,
	})
	c.JSON(http.StatusOK, totpEnrollResponse{
		Secret:      enrollment.Secret,
		OtpauthURI:  enrollment.OtpauthURI,
		AccountName: enrollment.AccountName,
	})
}

// VerifyTOTP confirms the code against the pending secret and flips
// totp_enabled to true. 404 when the user has no pending enrollment;
// 401 when the code is wrong.
func (h *AuthHandler) VerifyTOTP(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		writeError(c, http.StatusUnauthorized, apierror.CodeUnauthorized, "unauthenticated")
		return
	}
	var req totpVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, err.Error())
		return
	}
	ctx := c.Request.Context()

	_, cipher, err := h.Users.GetTOTP(ctx, principal.UserID)
	if err != nil {
		slog.ErrorContext(ctx, "totp verify: lookup", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	if len(cipher) == 0 {
		writeError(c, http.StatusNotFound, apierror.CodeTOTPNotEnrolled, "no pending enrollment")
		return
	}
	secret, err := h.AEAD.Open(cipher, totpSecretAD)
	if err != nil {
		slog.ErrorContext(ctx, "totp verify: decrypt", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	if !auth.ValidateTOTP(string(secret), req.Code) {
		h.Audit.Log(ctx, repository.AuditEntry{
			ActorUserID: &principal.UserID, ActorIP: clientIP(c), ActorUA: c.Request.UserAgent(),
			Action: "auth.totp_verify", TargetType: "user", TargetID: principal.UserID.String(),
			Result: repository.AuditResultFailure, ErrorMessage: "code mismatch",
		})
		writeError(c, http.StatusUnauthorized, apierror.CodeTOTPInvalid, "invalid totp code")
		return
	}
	if err := h.Users.EnableTOTP(ctx, principal.UserID); err != nil {
		slog.ErrorContext(ctx, "totp verify: enable", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	h.Audit.Log(ctx, repository.AuditEntry{
		ActorUserID: &principal.UserID, ActorIP: clientIP(c), ActorUA: c.Request.UserAgent(),
		Action: "auth.totp_verify", TargetType: "user", TargetID: principal.UserID.String(),
		Result: repository.AuditResultSuccess,
	})
	c.Status(http.StatusNoContent)
}

// DisableTOTP clears the secret and flips enabled=false after
// re-verifying password + current code. Requiring both defeats a
// stolen-session attacker from disabling 2FA on a victim's account
// without the device.
func (h *AuthHandler) DisableTOTP(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		writeError(c, http.StatusUnauthorized, apierror.CodeUnauthorized, "unauthenticated")
		return
	}
	var req totpDisableRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, err.Error())
		return
	}
	ctx := c.Request.Context()

	hash, err := h.Users.GetPasswordHash(ctx, principal.UserID)
	if err != nil {
		writeError(c, http.StatusUnauthorized, apierror.CodeUnauthorized, "unauthenticated")
		return
	}
	matches, err := auth.VerifyPassword(req.Password, hash)
	if err != nil || !matches {
		writeError(c, http.StatusUnauthorized, apierror.CodeInvalidCredentials, "password incorrect")
		return
	}

	enabled, cipher, err := h.Users.GetTOTP(ctx, principal.UserID)
	if err != nil {
		slog.ErrorContext(ctx, "totp disable: lookup", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	if !enabled || len(cipher) == 0 {
		writeError(c, http.StatusNotFound, apierror.CodeTOTPNotEnrolled, "totp is not enabled")
		return
	}
	secret, err := h.AEAD.Open(cipher, totpSecretAD)
	if err != nil {
		slog.ErrorContext(ctx, "totp disable: decrypt", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	if !auth.ValidateTOTP(string(secret), req.Code) {
		writeError(c, http.StatusUnauthorized, apierror.CodeTOTPInvalid, "invalid totp code")
		return
	}
	if err := h.Users.ClearTOTP(ctx, principal.UserID); err != nil {
		slog.ErrorContext(ctx, "totp disable: clear", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	h.Audit.Log(ctx, repository.AuditEntry{
		ActorUserID: &principal.UserID, ActorIP: clientIP(c), ActorUA: c.Request.UserAgent(),
		Action: "auth.totp_disable", TargetType: "user", TargetID: principal.UserID.String(),
		Result: repository.AuditResultSuccess,
	})
	c.Status(http.StatusNoContent)
}
