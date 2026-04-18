//go:build integration
// +build integration

package handler_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/auth"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/crypto"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/dbtest"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/handler"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/repository"
)

// wgEnv is the WG-aware variant of env. We don't reuse env because
// router-with-wg-deps changes its construction; sharing would force every
// auth test to also build a crypto.AEAD.
type wgEnv struct {
	router *gin.Engine
	pool   *pgxpool.Pool
	aead   *crypto.AEAD
	access string
	userID uuid.UUID
}

func setupWG(t *testing.T) *wgEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	pool := dbtest.Fresh(t)

	issuer, err := auth.NewJWTIssuer(jwtSecret, accessTTL)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}

	rawKey := make([]byte, crypto.KeyLen)
	if _, err := rand.Read(rawKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	aead, err := crypto.New(rawKey)
	if err != nil {
		t.Fatalf("aead: %v", err)
	}

	const email = "wg@example.com"
	const password = "wireguard-test-password-123"
	userID := createUser(t, pool, email, "wg", password, "admin")

	router := handler.NewRouter(handler.Deps{
		JWTIssuer:  issuer,
		Users:      repository.NewUserRepo(pool),
		Sessions:   repository.NewSessionRepo(pool),
		Audit:      repository.NewAuditRepo(pool),
		Interfaces: repository.NewInterfaceRepo(pool),
		Peers:      repository.NewPeerRepo(pool),
		AEAD:       aead,
		RefreshTTL: refreshTTL,
	})

	e := &wgEnv{router: router, pool: pool, aead: aead, userID: userID}
	// Log in to get an access token. The auth-test env helpers expect their
	// own env type, so reproduce the bare login here.
	tk := loginRaw(t, router, email, password)
	e.access = tk.AccessToken
	return e
}

func loginRaw(t *testing.T, r *gin.Engine, email, pw string) tokens {
	t.Helper()
	w := callJSON(t, r, http.MethodPost, "/api/v1/auth/login",
		gin.H{"email": email, "password": pw}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("login failed: %d body=%s", w.Code, w.Body.String())
	}
	var tk tokens
	if err := json.Unmarshal(w.Body.Bytes(), &tk); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return tk
}

func callJSON(t *testing.T, r *gin.Engine, method, path string, body any, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	var buf []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		buf = b
	}
	return doRaw(t, r, method, path, buf, bearer)
}

func doRaw(t *testing.T, r *gin.Engine, method, path string, body []byte, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestCreateInterfaceGeneratesKeysAndEncryptsPrivate(t *testing.T) {
	e := setupWG(t)

	w := callJSON(t, e.router, http.MethodPost, "/api/v1/interfaces", gin.H{
		"name":        "wg0",
		"listen_port": 51820,
		"address":     "10.8.0.1/24",
	}, e.access)
	if w.Code != http.StatusCreated {
		t.Fatalf("create iface: %d body=%s", w.Code, w.Body.String())
	}

	var resp struct {
		ID        string `json:"id"`
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.PublicKey) != 44 || !strings.HasSuffix(resp.PublicKey, "=") {
		t.Errorf("public key shape: %q", resp.PublicKey)
	}

	// Private key is encrypted at rest — i.e. the BYTEA in the row must NOT
	// equal any plausible plaintext (specifically: it should be 12-byte nonce
	// + ciphertext + 16-byte GCM tag = at least 28 bytes longer than 32).
	var stored []byte
	if err := e.pool.QueryRow(context.Background(),
		`SELECT private_key FROM wg_interfaces WHERE id = $1`, resp.ID,
	).Scan(&stored); err != nil {
		t.Fatalf("query private_key: %v", err)
	}
	if len(stored) <= 32 {
		t.Errorf("private_key not encrypted (len=%d)", len(stored))
	}
	// And it must decrypt under the AEAD bound to interface AAD.
	plain, err := e.aead.Open(stored, []byte("wg_interfaces.private_key"))
	if err != nil {
		t.Fatalf("open stored key: %v", err)
	}
	if len(plain) != 32 {
		t.Errorf("decrypted key length: %d, want 32", len(plain))
	}
}

func TestCreateInterfaceDuplicateName(t *testing.T) {
	e := setupWG(t)
	body := gin.H{"name": "wg0", "listen_port": 51820, "address": "10.8.0.1/24"}
	if w := callJSON(t, e.router, http.MethodPost, "/api/v1/interfaces", body, e.access); w.Code != http.StatusCreated {
		t.Fatalf("first create: %d", w.Code)
	}
	w := callJSON(t, e.router, http.MethodPost, "/api/v1/interfaces", body, e.access)
	if w.Code != http.StatusConflict {
		t.Errorf("duplicate name: got %d, want 409", w.Code)
	}
}

func TestCreatePeerAllocatesNextFreeIP(t *testing.T) {
	e := setupWG(t)
	ifaceID := mustCreateInterface(t, e, "wg0", "10.8.0.1/24")

	// First peer: should land on .2 (interface holds .1, .0/.255 reserved).
	w := callJSON(t, e.router, http.MethodPost, "/api/v1/peers", gin.H{
		"interface_id": ifaceID,
		"name":         "alice",
	}, e.access)
	if w.Code != http.StatusCreated {
		t.Fatalf("create peer: %d body=%s", w.Code, w.Body.String())
	}
	var p struct {
		AssignedIP string `json:"assigned_ip"`
		PublicKey  string `json:"public_key"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.AssignedIP != "10.8.0.2" {
		t.Errorf("first peer ip: got %s, want 10.8.0.2", p.AssignedIP)
	}

	// Second peer: .3.
	w2 := callJSON(t, e.router, http.MethodPost, "/api/v1/peers", gin.H{
		"interface_id": ifaceID,
		"name":         "bob",
	}, e.access)
	var p2 struct {
		AssignedIP string `json:"assigned_ip"`
	}
	_ = json.Unmarshal(w2.Body.Bytes(), &p2)
	if p2.AssignedIP != "10.8.0.3" {
		t.Errorf("second peer ip: got %s, want 10.8.0.3", p2.AssignedIP)
	}
}

func TestCreatePeerWithSuppliedPublicKeyDoesNotStorePrivate(t *testing.T) {
	e := setupWG(t)
	ifaceID := mustCreateInterface(t, e, "wg0", "10.8.0.1/24")

	// 32 zero bytes → valid 44-char base64 ending in '='.
	pub := base64.StdEncoding.EncodeToString(make([]byte, 32))

	w := callJSON(t, e.router, http.MethodPost, "/api/v1/peers", gin.H{
		"interface_id": ifaceID,
		"name":         "byok",
		"public_key":   pub,
	}, e.access)
	if w.Code != http.StatusCreated {
		t.Fatalf("create peer: %d body=%s", w.Code, w.Body.String())
	}

	var stored []byte
	if err := e.pool.QueryRow(context.Background(),
		`SELECT private_key FROM wg_peers WHERE name = 'byok'`,
	).Scan(&stored); err != nil {
		t.Fatalf("query: %v", err)
	}
	if stored != nil {
		t.Errorf("expected NULL private_key for BYOK peer, got %d bytes", len(stored))
	}
}

func TestPeerConfigContainsExpectedSections(t *testing.T) {
	e := setupWG(t)
	ifaceID := mustCreateInterface(t, e, "wg0", "10.8.0.1/24")

	w := callJSON(t, e.router, http.MethodPost, "/api/v1/peers", gin.H{
		"interface_id": ifaceID,
		"name":         "alice",
	}, e.access)
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)

	cfg := doRaw(t, e.router, http.MethodGet, "/api/v1/peers/"+created.ID+"/config", nil, e.access)
	if cfg.Code != http.StatusOK {
		t.Fatalf("config: %d body=%s", cfg.Code, cfg.Body.String())
	}
	body := cfg.Body.String()
	for _, want := range []string{"[Interface]", "PrivateKey =", "Address = 10.8.0.2", "[Peer]", "PublicKey =", "AllowedIPs ="} {
		if !strings.Contains(body, want) {
			t.Errorf("config missing %q\n%s", want, body)
		}
	}
	// PNG variant.
	png := doRaw(t, e.router, http.MethodGet, "/api/v1/peers/"+created.ID+"/config.png", nil, e.access)
	if png.Code != http.StatusOK {
		t.Fatalf("qr: %d", png.Code)
	}
	if ct := png.Header().Get("Content-Type"); ct != "image/png" {
		t.Errorf("qr content-type: %q", ct)
	}
	if !strings.HasPrefix(png.Body.String(), "\x89PNG") {
		t.Error("qr body is not a PNG")
	}
}

func TestDeleteInterfaceCascadesPeers(t *testing.T) {
	e := setupWG(t)
	ifaceID := mustCreateInterface(t, e, "wg0", "10.8.0.1/24")
	w := callJSON(t, e.router, http.MethodPost, "/api/v1/peers", gin.H{
		"interface_id": ifaceID, "name": "alice",
	}, e.access)
	if w.Code != http.StatusCreated {
		t.Fatalf("seed peer: %d", w.Code)
	}

	w = doRaw(t, e.router, http.MethodDelete, "/api/v1/interfaces/"+ifaceID, nil, e.access)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete iface: %d body=%s", w.Code, w.Body.String())
	}

	var n int
	if err := e.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM wg_peers WHERE interface_id = $1`,
		uuid.MustParse(ifaceID),
	).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("cascade left %d peers", n)
	}
}

func TestNonAdminUserForbidden(t *testing.T) {
	e := setupWG(t)
	// Demote and re-login.
	if _, err := e.pool.Exec(context.Background(),
		`UPDATE users SET role = 'user' WHERE id = $1`, e.userID,
	); err != nil {
		t.Fatalf("demote: %v", err)
	}
	tk := loginRaw(t, e.router, "wg@example.com", "wireguard-test-password-123")
	w := callJSON(t, e.router, http.MethodGet, "/api/v1/interfaces", nil, tk.AccessToken)
	if w.Code != http.StatusForbidden {
		t.Errorf("plain user should be forbidden, got %d", w.Code)
	}
}

func mustCreateInterface(t *testing.T, e *wgEnv, name, addr string) string {
	t.Helper()
	w := callJSON(t, e.router, http.MethodPost, "/api/v1/interfaces", gin.H{
		"name": name, "listen_port": 51820, "address": addr,
	}, e.access)
	if w.Code != http.StatusCreated {
		t.Fatalf("create iface: %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return resp.ID
}
