//go:build integration
// +build integration

package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/auth"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/dbtest"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/handler"
	mw "github.com/tomeksdev/wireguard-install-with-gui/backend/internal/middleware"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/repository"
)

const (
	jwtSecret  = "test-secret-that-is-at-least-32-bytes-long!"
	accessTTL  = 2 * time.Minute
	refreshTTL = 24 * time.Hour
)

type env struct {
	router *gin.Engine
	pool   *pgxpool.Pool
	userID uuid.UUID
	email  string
	pass   string
	role   string
}

func setup(t *testing.T) *env {
	t.Helper()
	gin.SetMode(gin.TestMode)
	pool := dbtest.Fresh(t)

	issuer, err := auth.NewJWTIssuer(jwtSecret, accessTTL)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}

	e := &env{
		pool:  pool,
		email: "user@example.com",
		pass:  "correct-horse-battery-staple",
		role:  "admin",
	}
	e.userID = createUser(t, pool, e.email, "u1", e.pass, e.role)

	e.router = handler.NewRouter(handler.Deps{
		JWTIssuer:  issuer,
		Users:      repository.NewUserRepo(pool),
		Sessions:   repository.NewSessionRepo(pool),
		Audit:      repository.NewAuditRepo(pool),
		RefreshTTL: refreshTTL,
		// Default: limits disabled so existing auth tests aren't flaky
		// under bursts. TestLoginRateLimit builds its own router with limits on.
	})
	return e
}

func createUser(t *testing.T, pool *pgxpool.Pool, email, username, password, role string) uuid.UUID {
	t.Helper()
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	var id uuid.UUID
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (email, username, password_hash, role)
		 VALUES ($1, $2, $3, $4::user_role) RETURNING id`,
		email, username, hash, role,
	).Scan(&id); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	return id
}

type tokens struct {
	AccessToken     string    `json:"access_token"`
	RefreshToken    string    `json:"refresh_token"`
	AccessExpiresAt time.Time `json:"access_expires_at"`
	Role            string    `json:"role"`
}

func do(t *testing.T, e *env, method, path string, body any, bearer string) (*httptest.ResponseRecorder, []byte) {
	t.Helper()
	var buf *bytes.Buffer
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		buf = bytes.NewBuffer(b)
	} else {
		buf = bytes.NewBuffer(nil)
	}
	req := httptest.NewRequest(method, path, buf)
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	return w, w.Body.Bytes()
}

func login(t *testing.T, e *env, email, password string) (*httptest.ResponseRecorder, tokens) {
	t.Helper()
	w, body := do(t, e, http.MethodPost, "/api/v1/auth/login", gin.H{
		"email": email, "password": password,
	}, "")
	if w.Code != http.StatusOK {
		return w, tokens{}
	}
	var tk tokens
	if err := json.Unmarshal(body, &tk); err != nil {
		t.Fatalf("unmarshal tokens: %v body=%s", err, string(body))
	}
	return w, tk
}

func TestLoginHappyPath(t *testing.T) {
	e := setup(t)
	w, tk := login(t, e, e.email, e.pass)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d body=%s", w.Code, w.Body.String())
	}
	if tk.AccessToken == "" || tk.RefreshToken == "" {
		t.Fatal("expected both tokens in response")
	}
	if tk.Role != e.role {
		t.Errorf("role: got %q want %q", tk.Role, e.role)
	}
	if !tk.AccessExpiresAt.After(time.Now()) {
		t.Error("access_expires_at should be in the future")
	}

	// last_login_at is stamped.
	var last *time.Time
	if err := e.pool.QueryRow(context.Background(),
		`SELECT last_login_at FROM users WHERE id = $1`, e.userID,
	).Scan(&last); err != nil || last == nil {
		t.Errorf("last_login_at not stamped: %v", err)
	}
}

func TestLoginBadPassword(t *testing.T) {
	e := setup(t)
	w, _ := login(t, e, e.email, "wrong-password")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", w.Code)
	}

	var fails int
	if err := e.pool.QueryRow(context.Background(),
		`SELECT failed_logins FROM users WHERE id = $1`, e.userID,
	).Scan(&fails); err != nil {
		t.Fatalf("fails query: %v", err)
	}
	if fails != 1 {
		t.Errorf("failed_logins: got %d want 1", fails)
	}
}

func TestLoginLockoutAfterFiveFailures(t *testing.T) {
	e := setup(t)
	for i := 0; i < 5; i++ {
		login(t, e, e.email, "wrong")
	}
	// Next attempt must hit account-locked, even with the right password.
	w, _ := login(t, e, e.email, e.pass)
	if w.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want 403", w.Code)
	}
}

func TestLoginUnknownEmailReturns401(t *testing.T) {
	e := setup(t)
	w, _ := login(t, e, "nobody@example.com", "whatever")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401 (matching bad-password, no enumeration)", w.Code)
	}
}

func TestRefreshRotatesToken(t *testing.T) {
	e := setup(t)
	_, first := login(t, e, e.email, e.pass)

	w, body := do(t, e, http.MethodPost, "/api/v1/auth/refresh", gin.H{
		"refresh_token": first.RefreshToken,
	}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("refresh: got %d body=%s", w.Code, string(body))
	}
	var second tokens
	if err := json.Unmarshal(body, &second); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if second.RefreshToken == first.RefreshToken {
		t.Error("refresh token should rotate on every refresh")
	}
	if second.AccessToken == "" {
		t.Error("expected new access token")
	}
}

func TestRefreshReuseRevokesSession(t *testing.T) {
	e := setup(t)
	_, first := login(t, e, e.email, e.pass)

	// Legitimate rotation: old → new.
	w1, _ := do(t, e, http.MethodPost, "/api/v1/auth/refresh", gin.H{
		"refresh_token": first.RefreshToken,
	}, "")
	if w1.Code != http.StatusOK {
		t.Fatalf("first refresh: %d", w1.Code)
	}

	// Reuse the original token — must be rejected AND the session revoked.
	w2, body := do(t, e, http.MethodPost, "/api/v1/auth/refresh", gin.H{
		"refresh_token": first.RefreshToken,
	}, "")
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("reuse: got %d, want 401 body=%s", w2.Code, string(body))
	}

	var envelope struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(body, &envelope)
	if envelope.Code != "REFRESH_REUSED" {
		t.Errorf("code: got %q, want REFRESH_REUSED", envelope.Code)
	}

	// Every session for the user must now be revoked.
	var active int
	if err := e.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`,
		e.userID,
	).Scan(&active); err != nil {
		t.Fatalf("count: %v", err)
	}
	if active != 0 {
		t.Errorf("expected session family revoked, got %d active", active)
	}
}

func TestLogoutRevokesSession(t *testing.T) {
	e := setup(t)
	_, tk := login(t, e, e.email, e.pass)

	w, _ := do(t, e, http.MethodPost, "/api/v1/auth/logout", gin.H{
		"refresh_token": tk.RefreshToken,
	}, "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("logout: got %d", w.Code)
	}

	// After logout the access token should be refused — session is revoked.
	w2, _ := do(t, e, http.MethodPost, "/api/v1/auth/password", gin.H{
		"current_password": e.pass, "new_password": "another-long-password-123",
	}, tk.AccessToken)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 after logout, got %d", w2.Code)
	}
}

func TestChangePasswordRevokesAllSessions(t *testing.T) {
	e := setup(t)
	_, tk1 := login(t, e, e.email, e.pass)
	_, tk2 := login(t, e, e.email, e.pass) // second session in parallel

	newPW := "new-strong-password-456"
	w, body := do(t, e, http.MethodPost, "/api/v1/auth/password", gin.H{
		"current_password": e.pass, "new_password": newPW,
	}, tk1.AccessToken)
	if w.Code != http.StatusNoContent {
		t.Fatalf("change password: %d body=%s", w.Code, string(body))
	}

	// Old password fails.
	wOld, _ := login(t, e, e.email, e.pass)
	if wOld.Code != http.StatusUnauthorized {
		t.Errorf("old password still works: %d", wOld.Code)
	}

	// New password works.
	wNew, _ := login(t, e, e.email, newPW)
	if wNew.Code != http.StatusOK {
		t.Errorf("new password failed: %d", wNew.Code)
	}

	// Second (parallel) session revoked.
	wStale := bearerCall(t, e, tk2.AccessToken)
	if wStale.Code != http.StatusUnauthorized {
		t.Errorf("parallel session not revoked: %d", wStale.Code)
	}
}

func TestRequireRoleGating(t *testing.T) {
	e := setup(t)
	e.router = buildRouterWithAdminOnlyEcho(t, e)
	_, tk := login(t, e, e.email, e.pass)

	// admin role allowed.
	wAdmin := getEcho(t, e, tk.AccessToken)
	if wAdmin.Code != http.StatusOK {
		t.Errorf("admin denied: %d", wAdmin.Code)
	}

	// Demote user to plain 'user' and re-login → role in token is 'user' now.
	if _, err := e.pool.Exec(context.Background(),
		`UPDATE users SET role = 'user' WHERE id = $1`, e.userID,
	); err != nil {
		t.Fatalf("demote: %v", err)
	}
	_, tk2 := login(t, e, e.email, e.pass)

	wUser := getEcho(t, e, tk2.AccessToken)
	if wUser.Code != http.StatusForbidden {
		t.Errorf("plain user should be forbidden: %d", wUser.Code)
	}
}

// buildRouterWithAdminOnlyEcho rebuilds the router with an extra GET
// /api/v1/admin/echo route protected by RequireRole("super_admin","admin").
// We do this via a helper because the production NewRouter doesn't expose
// a test-only route — the point here is to verify RequireRole in isolation.
func buildRouterWithAdminOnlyEcho(t *testing.T, e *env) *gin.Engine {
	t.Helper()
	// Rebuild from scratch so we don't carry handler state from setup().
	issuer, err := auth.NewJWTIssuer(jwtSecret, accessTTL)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}

	deps := handler.Deps{
		JWTIssuer:  issuer,
		Users:      repository.NewUserRepo(e.pool),
		Sessions:   repository.NewSessionRepo(e.pool),
		Audit:      repository.NewAuditRepo(e.pool),
		RefreshTTL: refreshTTL,
	}
	r := handler.NewRouter(deps)

	admin := r.Group("/api/v1/admin")
	admin.Use(
		mwRequireAuth(issuer, deps.Sessions),
		mwRequireRole("super_admin", "admin"),
	)
	admin.GET("/echo", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func getEcho(t *testing.T, e *env, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	w, _ := do(t, e, http.MethodGet, "/api/v1/admin/echo", nil, bearer)
	return w
}

func bearerCall(t *testing.T, e *env, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	w, _ := do(t, e, http.MethodPost, "/api/v1/auth/password", gin.H{
		"current_password": "ignored", "new_password": "ignored-long-pass-0",
	}, bearer)
	return w
}

func TestLoginRateLimitRejectsBurst(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := dbtest.Fresh(t)

	issuer, err := auth.NewJWTIssuer(jwtSecret, accessTTL)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	email := "rl@example.com"
	pw := "rate-limit-password-123"
	createUser(t, pool, email, "rl", pw, "admin")

	router := handler.NewRouter(handler.Deps{
		JWTIssuer:  issuer,
		Users:      repository.NewUserRepo(pool),
		Sessions:   repository.NewSessionRepo(pool),
		Audit:      repository.NewAuditRepo(pool),
		RefreshTTL: refreshTTL,
		LoginLimit: mw.RateLimitConfig{
			Name:      "login",
			PerMinute: 60,
			Burst:     2,
		},
	})

	postLogin := func(payload any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "192.0.2.1:4444"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	// Two bad attempts consume the burst.
	for i := 0; i < 2; i++ {
		w := postLogin(gin.H{"email": email, "password": "bad"})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("burst #%d: got %d, want 401", i+1, w.Code)
		}
	}
	// Third must be rate-limited even if the credentials are valid.
	w := postLogin(gin.H{"email": email, "password": pw})
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after burst, got %d body=%s", w.Code, w.Body.String())
	}
	if ra := w.Header().Get("Retry-After"); ra == "" {
		t.Error("missing Retry-After on 429")
	}

	// Rate-limit denial is in the audit log.
	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE action = 'auth.login' AND result = 'denied'`,
	).Scan(&count); err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if count < 1 {
		t.Error("expected a rate-limit denial row in audit_log")
	}
}

func mwRequireAuth(j *auth.JWTIssuer, s *repository.SessionRepo) gin.HandlerFunc {
	return mw.RequireAuth(j, s)
}
func mwRequireRole(roles ...string) gin.HandlerFunc {
	return mw.RequireRole(roles...)
}
