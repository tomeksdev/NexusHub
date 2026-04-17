package handler

import (
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/auth"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/middleware"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/repository"
)

// Deps bundles everything the router needs so cmd/api/main.go has a single
// constructor call.
type Deps struct {
	JWTIssuer  *auth.JWTIssuer
	Users      *repository.UserRepo
	Sessions   *repository.SessionRepo
	Audit      *repository.AuditRepo
	RefreshTTL time.Duration
}

// NewRouter builds the Gin engine with all middleware and routes registered.
// We deliberately do NOT use gin.Default() — it installs Gin's own logger,
// which we replace with a slog-backed one.
func NewRouter(deps Deps) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery(), accessLog())

	authH := &AuthHandler{
		Users: deps.Users, Sessions: deps.Sessions, Audit: deps.Audit,
		JWT: deps.JWTIssuer, RefreshTTL: deps.RefreshTTL,
	}

	v1 := r.Group("/api/v1")
	v1.GET("/health", Health)

	// Public auth endpoints.
	authGrp := v1.Group("/auth")
	authGrp.POST("/login", authH.Login)
	authGrp.POST("/refresh", authH.Refresh)
	authGrp.POST("/logout", authH.Logout)

	// Authenticated auth endpoints.
	authed := v1.Group("")
	authed.Use(middleware.RequireAuth(deps.JWTIssuer, deps.Sessions))
	authed.POST("/auth/password", authH.ChangePassword)

	return r
}

func accessLog() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		slog.Info("http",
			"method", c.Request.Method,
			"path", c.FullPath(),
			"status", c.Writer.Status(),
			"dur_ms", time.Since(start).Milliseconds(),
			"ip", c.ClientIP(),
		)
	}
}
