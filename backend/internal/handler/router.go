package handler

import (
	"log/slog"
	"net"
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

	// Rate-limit configs. Pass zero-value RateLimitConfig to disable a given
	// limiter; the middleware itself decides this based on PerMinute == 0.
	LoginLimit   middleware.RateLimitConfig
	RefreshLimit middleware.RateLimitConfig
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

	// Public auth endpoints. Login and refresh are the only attackable surface
	// before authentication, so they get per-IP rate limiting.
	loginCfg := deps.LoginLimit
	if loginCfg.Name == "" {
		loginCfg.Name = "login"
	}
	refreshCfg := deps.RefreshLimit
	if refreshCfg.Name == "" {
		refreshCfg.Name = "refresh"
	}
	if deps.Audit != nil {
		loginCfg.OnDeny = auditDeny(deps.Audit, "auth.login")
		refreshCfg.OnDeny = auditDeny(deps.Audit, "auth.refresh")
	}
	loginLimiter := middleware.NewRateLimiter(loginCfg)
	refreshLimiter := middleware.NewRateLimiter(refreshCfg)

	authGrp := v1.Group("/auth")
	authGrp.POST("/login", loginLimiter.Middleware(), authH.Login)
	authGrp.POST("/refresh", refreshLimiter.Middleware(), authH.Refresh)
	authGrp.POST("/logout", authH.Logout)

	// Authenticated auth endpoints.
	authed := v1.Group("")
	authed.Use(middleware.RequireAuth(deps.JWTIssuer, deps.Sessions))
	authed.POST("/auth/password", authH.ChangePassword)

	return r
}

// auditDeny returns an OnDeny callback that emits a rate-limit denial to
// the audit log. We deliberately use the request context (not Background)
// so a cancelled request also cancels the audit write — a per-request
// limiter denial is not worth keeping the DB connection alive past the
// client disconnect.
func auditDeny(a *repository.AuditRepo, action string) func(*gin.Context) {
	return func(c *gin.Context) {
		ip := net.ParseIP(c.ClientIP())
		a.Log(c.Request.Context(), repository.AuditEntry{
			ActorIP: ip, ActorUA: c.Request.UserAgent(),
			Action: action, TargetType: "rate_limit",
			Result: repository.AuditResultDenied, ErrorMessage: "rate limit exceeded",
		})
	}
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
