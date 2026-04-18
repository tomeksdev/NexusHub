// Package apierror defines the JSON error envelope and stable error codes
// shared by handlers and middleware. Keeping this in its own package breaks
// the handler ⇄ middleware import cycle that would otherwise exist.
package apierror

import "github.com/gin-gonic/gin"

// Body is the JSON error envelope per CLAUDE.md: {"error": "...", "code": "..."}.
type Body struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// Error codes. Keep stable — the frontend switches on them.
const (
	CodeInvalidRequest     = "INVALID_REQUEST"
	CodeInvalidCredentials = "INVALID_CREDENTIALS"
	CodeAccountLocked      = "ACCOUNT_LOCKED"
	CodeAccountDisabled    = "ACCOUNT_DISABLED"
	CodeUnauthorized       = "UNAUTHORIZED"
	CodeForbidden          = "FORBIDDEN"
	CodeRefreshInvalid     = "REFRESH_INVALID"
	CodeRefreshReused      = "REFRESH_REUSED"
	CodeRateLimited        = "RATE_LIMITED"
	CodeNotFound           = "NOT_FOUND"
	CodeConflict           = "CONFLICT"
	CodePoolExhausted      = "IP_POOL_EXHAUSTED"
	CodeInternal           = "INTERNAL"
)

// Write aborts the request with the given status and envelope.
func Write(c *gin.Context, status int, code, msg string) {
	c.AbortWithStatusJSON(status, Body{Error: msg, Code: code})
}
