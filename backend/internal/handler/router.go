package handler

import (
	"log/slog"
	"net"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/auth"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/crypto"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/metrics"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/middleware"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/openapi"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/repository"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/wg"
)

// Deps bundles everything the router needs so cmd/api/main.go has a single
// constructor call.
type Deps struct {
	JWTIssuer  *auth.JWTIssuer
	Users      *repository.UserRepo
	Sessions   *repository.SessionRepo
	Audit      *repository.AuditRepo
	Interfaces *repository.InterfaceRepo
	Peers      *repository.PeerRepo
	AEAD       *crypto.AEAD
	RefreshTTL time.Duration

	// WG bridges the DB to the live kernel device. Nil in tests and dev
	// environments without the kernel module — handlers skip kernel sync
	// and remain DB-only.
	WG wg.Client
	// DefaultWGEndpoint and DefaultWGDNS feed the wg-quick config
	// renderer's fall-back chain (peer → interface → default). They're
	// sourced from WG_ENDPOINT and the interface DNS column respectively.
	DefaultWGEndpoint string
	DefaultWGDNS      []string

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
	r.Use(gin.Recovery(), middleware.RequestID(), metrics.Middleware(), accessLog())

	authH := &AuthHandler{
		Users: deps.Users, Sessions: deps.Sessions, Audit: deps.Audit,
		JWT: deps.JWTIssuer, RefreshTTL: deps.RefreshTTL,
	}

	v1 := r.Group("/api/v1")
	v1.GET("/health", Health)
	// OpenAPI spec — intentionally public so SDK generators and frontend
	// codegen tools can fetch without a token. The spec itself doesn't
	// leak configuration; it only describes shapes.
	v1.GET("/openapi.yaml", func(c *gin.Context) {
		c.Data(200, openapi.SpecContentType, openapi.Spec)
	})

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

	// WireGuard CRUD — admin/super_admin only. The config + QR exports are
	// in the same group; an authenticated non-admin should not be able to
	// download a config they didn't create.
	if deps.Interfaces != nil && deps.Peers != nil && deps.AEAD != nil {
		ifaceH := &InterfaceHandler{
			Interfaces: deps.Interfaces, AEAD: deps.AEAD, Client: deps.WG,
		}
		peerH := &PeerHandler{
			Peers: deps.Peers, Interfaces: deps.Interfaces, AEAD: deps.AEAD,
			Client:          deps.WG,
			DefaultEndpoint: deps.DefaultWGEndpoint,
			DefaultDNS:      deps.DefaultWGDNS,
		}
		statusH := &StatusHandler{Client: deps.WG, Interfaces: deps.Interfaces}

		admin := authed.Group("")
		admin.Use(middleware.RequireRole("super_admin", "admin"))
		admin.GET("/interfaces", ifaceH.List)
		admin.POST("/interfaces", ifaceH.Create)
		admin.GET("/interfaces/:id", ifaceH.Get)
		admin.DELETE("/interfaces/:id", ifaceH.Delete)

		admin.GET("/peers", peerH.List)
		admin.POST("/peers", peerH.Create)
		admin.GET("/peers/:id", peerH.Get)
		admin.DELETE("/peers/:id", peerH.Delete)
		admin.POST("/peers/:id/rotate-psk", peerH.RotatePSK)
		admin.GET("/peers/:id/config", peerH.Config)
		admin.GET("/peers/:id/config.png", peerH.ConfigQR)

		admin.GET("/wg/status", statusH.Status)
		admin.GET("/metrics", metrics.Handler())

		// Live peer state — same admin gate as wg/status; leaks handshake
		// times and byte counters that should stay behind auth.
		eventsH := &PeerEventsHandler{Client: deps.WG, Interfaces: deps.Interfaces}
		admin.GET("/peers/events", eventsH.Events)
	}

	// Users + audit-log list endpoints. Behind the same role gate as
	// WireGuard CRUD so a regular user with a valid JWT can't enumerate
	// accounts or scrape the action history.
	admin := authed.Group("")
	admin.Use(middleware.RequireRole("super_admin", "admin"))
	if deps.Users != nil {
		userH := &UserHandler{Users: deps.Users}
		admin.GET("/users", userH.List)
	}
	if deps.Audit != nil {
		auditH := &AuditHandler{Audit: deps.Audit}
		admin.GET("/audit-log", auditH.List)
	}

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
		attrs := []any{
			"method", c.Request.Method,
			"path", c.FullPath(),
			"status", c.Writer.Status(),
			"dur_ms", time.Since(start).Milliseconds(),
			"ip", c.ClientIP(),
			"request_id", middleware.RequestIDFromGin(c),
		}
		if corr := middleware.CorrelationIDFromContext(c.Request.Context()); corr != "" {
			attrs = append(attrs, "correlation_id", corr)
		}
		slog.Info("http", attrs...)
	}
}
