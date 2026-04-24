// Package client is the thin HTTP surface the CLI uses to talk to
// the NexusHub API. It owns auth header selection (API key takes
// precedence over access token), JSON envelope decoding, and the
// API error shape — resource commands consume typed methods, not
// raw requests.
package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/tomeksdev/NexusHub/cli/internal/config"
)

// Error mirrors the backend envelope {"error":"...","code":"..."}.
type Error struct {
	Status int
	Code   string
	Msg    string
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s (%d)", e.Code, e.Msg, e.Status) }

// Client wraps a net/http Client with the base URL and auth credentials
// from the on-disk config. Thread-safe: the underlying http.Client is
// safe for concurrent use and no mutable state lives on Client.
type Client struct {
	http   *http.Client
	base   string
	apiKey string
	token  string
}

// New builds a Client from the loaded config. An explicit server flag
// overrides the config URL — useful for running one command against a
// different environment without editing the file.
func New(cfg *config.File, serverOverride string) *Client {
	base := cfg.APIURL
	if serverOverride != "" {
		base = serverOverride
	}
	return &Client{
		http:   &http.Client{Timeout: 30 * time.Second},
		base:   strings.TrimRight(base, "/"),
		apiKey: cfg.APIKey,
		token:  cfg.AccessToken,
	}
}

// BaseURL returns the server URL the client is pointed at. Used by
// the CLI's informational prints ("logged into https://...").
func (c *Client) BaseURL() string { return c.base }

// Do issues req with auth applied. Body is the decoded response on
// success. Non-2xx responses produce an *Error with the parsed
// envelope when possible.
func (c *Client) Do(method, path string, body, out any) error {
	var buf io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal body: %w", err)
		}
		buf = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, c.base+path, buf)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// API key takes precedence over bearer token so unattended
	// automation can carry an API key alongside a stale bearer
	// without surprises.
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	} else if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		var env struct{ Error, Code string }
		_ = json.Unmarshal(raw, &env)
		return &Error{Status: resp.StatusCode, Code: env.Code, Msg: chooseMsg(env.Error, string(raw))}
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func chooseMsg(envelope, raw string) string {
	if envelope != "" {
		return envelope
	}
	// Fall back to the first 200 bytes of the body so operators get a
	// hint even when the server's response isn't shaped like our
	// envelope (e.g. a reverse proxy's 502 page).
	if len(raw) > 200 {
		return raw[:200] + "…"
	}
	return raw
}

// ---- Typed endpoints ------------------------------------------------------

type LoginResponse struct {
	AccessToken     string    `json:"access_token"`
	RefreshToken    string    `json:"refresh_token"`
	AccessExpiresAt time.Time `json:"access_expires_at"`
	Role            string    `json:"role"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code,omitempty"`
}

// Login posts credentials to /auth/login. Surfaces the TOTP_REQUIRED
// signal as a typed sentinel so the caller can prompt for the code
// and retry without string-matching on error codes.
func (c *Client) Login(email, password, totpCode string) (*LoginResponse, error) {
	var out LoginResponse
	err := c.Do("POST", "/api/v1/auth/login", loginRequest{
		Email: email, Password: password, TOTPCode: totpCode,
	}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// IsTOTPRequired is true when err came back from Login signalling the
// user has 2FA enabled and no code was supplied.
func IsTOTPRequired(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == "TOTP_REQUIRED"
}

// ListInterfaces fetches the paginated interface list.
func (c *Client) ListInterfaces(limit int) (*PageEnvelope[Interface], error) {
	var out PageEnvelope[Interface]
	err := c.Do("GET", fmt.Sprintf("/api/v1/interfaces?limit=%d", limit), nil, &out)
	return &out, err
}

// ListPeers fetches peers for the given interface.
func (c *Client) ListPeers(interfaceID string, limit int) (*PageEnvelope[Peer], error) {
	var out PageEnvelope[Peer]
	err := c.Do("GET",
		fmt.Sprintf("/api/v1/peers?interface_id=%s&limit=%d", interfaceID, limit),
		nil, &out)
	return &out, err
}

// ListRules fetches every rule regardless of active state. The active=true
// query filter is intentionally omitted so ops can see disabled rules too.
func (c *Client) ListRules(limit int) (*PageEnvelope[Rule], error) {
	var out PageEnvelope[Rule]
	err := c.Do("GET", fmt.Sprintf("/api/v1/rules?limit=%d&sort=-priority", limit), nil, &out)
	return &out, err
}

// ListUsers requires admin role; a non-admin token gets 403 and the
// typed *Error surfaces that verbatim.
func (c *Client) ListUsers(limit int) (*PageEnvelope[User], error) {
	var out PageEnvelope[User]
	err := c.Do("GET", fmt.Sprintf("/api/v1/users?limit=%d", limit), nil, &out)
	return &out, err
}

// ListAudit pulls the most recent audit entries, newest first.
func (c *Client) ListAudit(limit int) (*PageEnvelope[AuditEntry], error) {
	var out PageEnvelope[AuditEntry]
	err := c.Do("GET", fmt.Sprintf("/api/v1/audit-log?limit=%d&sort=-occurred_at", limit), nil, &out)
	return &out, err
}

// Health probes the unauthenticated health endpoint. Used by the
// doctor command to distinguish reachability failures from auth
// failures.
func (c *Client) Health() (*Health, error) {
	var out Health
	err := c.Do("GET", "/api/v1/health", nil, &out)
	return &out, err
}

// ---- Mutations ------------------------------------------------------------

// CreatePeerRequest mirrors the backend handler's binding. Only Name +
// InterfaceID are strictly required; everything else has server-side
// defaults (server-generated keys, auto-allocated IP, etc.).
type CreatePeerRequest struct {
	InterfaceID         string   `json:"interface_id"`
	Name                string   `json:"name"`
	Description         string   `json:"description,omitempty"`
	AssignedIP          string   `json:"assigned_ip,omitempty"`
	AllowedIPs          []string `json:"allowed_ips,omitempty"`
	Endpoint            string   `json:"endpoint,omitempty"`
	PersistentKeepAlive int      `json:"persistent_keepalive,omitempty"`
}

// CreatePeer creates a peer row and returns the server-generated
// record (including keypair and allocated IP when those were left
// for the server to fill in).
func (c *Client) CreatePeer(req CreatePeerRequest) (*Peer, error) {
	var out Peer
	err := c.Do("POST", "/api/v1/peers", req, &out)
	return &out, err
}

// DeletePeer removes a peer by ID. Returns nil on 204 or 404 —
// deleting a non-existent peer is idempotent from the caller's
// perspective.
func (c *Client) DeletePeer(id string) error {
	return c.Do("DELETE", "/api/v1/peers/"+id, nil, nil)
}

// CreateRuleRequest matches the backend's createRuleRequest.
// Pointer fields distinguish "omit" from "zero" — priority=0 is
// valid and means lowest priority, not unset.
type CreateRuleRequest struct {
	Name        string  `json:"name"`
	Description string  `json:"description,omitempty"`
	Action      string  `json:"action"`
	Direction   string  `json:"direction,omitempty"`
	Protocol    string  `json:"protocol,omitempty"`
	SrcCIDR     string  `json:"src_cidr,omitempty"`
	DstCIDR     string  `json:"dst_cidr,omitempty"`
	SrcPortFrom *int    `json:"src_port_from,omitempty"`
	SrcPortTo   *int    `json:"src_port_to,omitempty"`
	DstPortFrom *int    `json:"dst_port_from,omitempty"`
	DstPortTo   *int    `json:"dst_port_to,omitempty"`
	RatePPS     *int    `json:"rate_pps,omitempty"`
	RateBurst   *int    `json:"rate_burst,omitempty"`
	Priority    *int    `json:"priority,omitempty"`
	IsActive    *bool   `json:"is_active,omitempty"`
}

// CreateRule posts a rule. The backend validates enum values and
// returns a 400 with CodeInvalidRequest on bad input; that surfaces
// through client.Error verbatim.
func (c *Client) CreateRule(req CreateRuleRequest) (*Rule, error) {
	var out Rule
	err := c.Do("POST", "/api/v1/rules", req, &out)
	return &out, err
}

// UpdateRuleRequest carries the subset of fields the toggle + edit
// paths change. All fields are optional — PATCH semantics on the
// backend.
type UpdateRuleRequest struct {
	IsActive *bool `json:"is_active,omitempty"`
}

// UpdateRule PATCHes a rule. Used by `rule toggle` today; extending
// to full edit is additive when we add --name/--action flags.
func (c *Client) UpdateRule(id string, req UpdateRuleRequest) (*Rule, error) {
	var out Rule
	err := c.Do("PATCH", "/api/v1/rules/"+id, req, &out)
	return &out, err
}

// DeleteRule removes a rule. Idempotent on 404.
func (c *Client) DeleteRule(id string) error {
	return c.Do("DELETE", "/api/v1/rules/"+id, nil, nil)
}

// GetRule fetches a single rule by ID. Used by `rule toggle` so we
// can read the current is_active before flipping.
func (c *Client) GetRule(id string) (*Rule, error) {
	var out Rule
	err := c.Do("GET", "/api/v1/rules/"+id, nil, &out)
	return &out, err
}
