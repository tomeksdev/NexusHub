// Package middleware contains Gin middleware used by the backend router.
package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/apierror"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/auth"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/repository"
)

// Principal identifies the caller behind an authenticated request. Lives in
// the gin context under principalKey.
type Principal struct {
	UserID    uuid.UUID
	SessionID uuid.UUID
	Role      string
}

const principalKey = "nexushub.principal"

// RequireAuth validates the Bearer token, confirms the session is still
// active, and stores the Principal on the context. Aborts with 401 on any
// failure.
func RequireAuth(jwtIssuer *auth.JWTIssuer, sessions *repository.SessionRepo) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := bearerToken(c.GetHeader("Authorization"))
		if raw == "" {
			unauthorized(c, "missing bearer token")
			return
		}

		claims, err := jwtIssuer.ParseAccess(raw)
		if err != nil {
			unauthorized(c, "invalid token")
			return
		}

		active, err := sessions.SessionActive(c.Request.Context(), claims.SessionID)
		if err != nil {
			apierror.Write(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
			return
		}
		if !active {
			unauthorized(c, "session revoked")
			return
		}

		c.Set(principalKey, Principal{
			UserID:    claims.UserID,
			SessionID: claims.SessionID,
			Role:      claims.Role,
		})
		c.Next()
	}
}

// RequireRole accepts the request only if the principal's role is in the
// allowed set. Must be mounted after RequireAuth.
func RequireRole(roles ...string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		allowed[r] = struct{}{}
	}
	return func(c *gin.Context) {
		p, ok := PrincipalFrom(c)
		if !ok {
			unauthorized(c, "unauthenticated")
			return
		}
		if _, ok := allowed[p.Role]; !ok {
			apierror.Write(c, http.StatusForbidden, apierror.CodeForbidden, "forbidden")
			return
		}
		c.Next()
	}
}

// PrincipalFrom extracts the Principal stashed by RequireAuth.
func PrincipalFrom(c *gin.Context) (Principal, bool) {
	v, ok := c.Get(principalKey)
	if !ok {
		return Principal{}, false
	}
	p, ok := v.(Principal)
	return p, ok
}

func bearerToken(header string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}

func unauthorized(c *gin.Context, msg string) {
	apierror.Write(c, http.StatusUnauthorized, apierror.CodeUnauthorized, msg)
}
