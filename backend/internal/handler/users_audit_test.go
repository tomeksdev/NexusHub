//go:build integration
// +build integration

package handler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/tomeksdev/NexusHub/backend/internal/repository"
)

// These tests exercise the admin-only list endpoints at /api/v1/users and
// /api/v1/audit-log end-to-end against a real PostgreSQL via dbtest.Fresh.
// The setup() helper lives in auth_test.go and already builds a router with
// Users + Audit repos wired in.

type listUsersResp struct {
	Items []struct {
		ID           string `json:"id"`
		Email        string `json:"email"`
		Username     string `json:"username"`
		Role         string `json:"role"`
		IsActive     bool   `json:"is_active"`
		TOTPEnabled  bool   `json:"totp_enabled"`
		FailedLogins int    `json:"failed_logins"`
	} `json:"items"`
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

func TestListUsersReturnsSeededUser(t *testing.T) {
	e := setup(t)
	_, tk := login(t, e, e.email, e.pass)

	w, body := do(t, e, http.MethodGet, "/api/v1/users?limit=10", nil, tk.AccessToken)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d body=%s", w.Code, string(body))
	}
	var resp listUsersResp
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, string(body))
	}
	if resp.Total < 1 || len(resp.Items) < 1 {
		t.Fatalf("expected at least one user, got %+v", resp)
	}
	// The projection must not carry secrets. Unmarshal into a raw map and
	// assert password_hash/totp_secret never appear.
	var raw struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("raw unmarshal: %v", err)
	}
	for _, it := range raw.Items {
		for _, forbidden := range []string{"password_hash", "totp_secret"} {
			if _, ok := it[forbidden]; ok {
				t.Errorf("user list leaked %q field", forbidden)
			}
		}
	}
}

func TestListUsersRequiresAuth(t *testing.T) {
	e := setup(t)
	w, _ := do(t, e, http.MethodGet, "/api/v1/users", nil, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestListUsersForbiddenForPlainUser(t *testing.T) {
	e := setup(t)
	// Demote the seeded user from admin to 'user' and re-login so the JWT
	// carries the new role. Role is embedded in the access token — we can't
	// reuse the old tk.
	if _, err := e.pool.Exec(context.Background(),
		`UPDATE users SET role = 'user' WHERE id = $1`, e.userID,
	); err != nil {
		t.Fatalf("demote: %v", err)
	}
	_, tk := login(t, e, e.email, e.pass)

	w, _ := do(t, e, http.MethodGet, "/api/v1/users", nil, tk.AccessToken)
	if w.Code != http.StatusForbidden {
		t.Fatalf("plain user should be forbidden, got %d", w.Code)
	}
}

type listAuditResp struct {
	Items []struct {
		ID         int64     `json:"id"`
		OccurredAt time.Time `json:"occurred_at"`
		Action     string    `json:"action"`
		TargetType string    `json:"target_type"`
		Result     string    `json:"result"`
	} `json:"items"`
	Total  int    `json:"total"`
	Limit  int    `json:"limit"`
	Offset int    `json:"offset"`
	Sort   string `json:"sort"`
}

func TestListAuditIsNewestFirstByDefault(t *testing.T) {
	e := setup(t)
	_, tk := login(t, e, e.email, e.pass)
	audit := repository.NewAuditRepo(e.pool)

	// Seed three entries with clearly distinct actions. OccurredAt is set by
	// the DB default (now()), so chronological order == insertion order.
	for _, action := range []string{"test.one", "test.two", "test.three"} {
		audit.Log(context.Background(), repository.AuditEntry{
			Action: action, TargetType: "test", Result: repository.AuditResultSuccess,
		})
	}

	w, body := do(t, e, http.MethodGet, "/api/v1/audit-log?limit=10", nil, tk.AccessToken)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d body=%s", w.Code, string(body))
	}
	var resp listAuditResp
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, string(body))
	}
	if resp.Total < 3 {
		t.Fatalf("expected >= 3 audit rows, got %d", resp.Total)
	}
	// The three seeded rows must appear in reverse insertion order — this
	// is the "newest first" default behaviour the audit viewer depends on.
	var seenOrder []string
	for _, it := range resp.Items {
		if it.Action == "test.one" || it.Action == "test.two" || it.Action == "test.three" {
			seenOrder = append(seenOrder, it.Action)
		}
	}
	if len(seenOrder) != 3 {
		t.Fatalf("expected all three test actions in result, got %v", seenOrder)
	}
	want := []string{"test.three", "test.two", "test.one"}
	for i, a := range want {
		if seenOrder[i] != a {
			t.Errorf("order[%d]: got %q want %q (full: %v)", i, seenOrder[i], a, seenOrder)
		}
	}
}

func TestListAuditFiltersByActionAndResult(t *testing.T) {
	e := setup(t)
	_, tk := login(t, e, e.email, e.pass)
	audit := repository.NewAuditRepo(e.pool)

	audit.Log(context.Background(), repository.AuditEntry{
		Action: "peer.create", TargetType: "peer", Result: repository.AuditResultSuccess,
	})
	audit.Log(context.Background(), repository.AuditEntry{
		Action: "peer.create", TargetType: "peer", Result: repository.AuditResultFailure,
		ErrorMessage: "pool exhausted",
	})
	audit.Log(context.Background(), repository.AuditEntry{
		Action: "peer.delete", TargetType: "peer", Result: repository.AuditResultSuccess,
	})

	// action=peer.create should see two, result=failure narrows to one.
	w, body := do(t, e,
		http.MethodGet, "/api/v1/audit-log?action=peer.create&result=failure&limit=10",
		nil, tk.AccessToken)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d body=%s", w.Code, string(body))
	}
	var resp listAuditResp
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Total != 1 || len(resp.Items) != 1 {
		t.Fatalf("want exactly 1 match, got total=%d items=%d", resp.Total, len(resp.Items))
	}
	if resp.Items[0].Action != "peer.create" || resp.Items[0].Result != "failure" {
		t.Errorf("unexpected row: %+v", resp.Items[0])
	}
}

func TestListAuditRejectsBadResultEnum(t *testing.T) {
	e := setup(t)
	_, tk := login(t, e, e.email, e.pass)

	w, _ := do(t, e, http.MethodGet, "/api/v1/audit-log?result=kinda", nil, tk.AccessToken)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid result enum, got %d", w.Code)
	}
}

func TestListAuditRejectsBadSince(t *testing.T) {
	e := setup(t)
	_, tk := login(t, e, e.email, e.pass)

	w, _ := do(t, e, http.MethodGet, "/api/v1/audit-log?since=yesterday", nil, tk.AccessToken)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for non-RFC3339 since, got %d", w.Code)
	}
}
