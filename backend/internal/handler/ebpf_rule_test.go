//go:build integration
// +build integration

package handler_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// These tests exercise /api/v1/rules end-to-end against a real DB. The
// FakeSyncer on env.sync lets us assert that CRUD flows call the
// syncer in lockstep with the DB write — which is the whole point of
// the sync layer.

type ruleBody struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Action      string  `json:"action"`
	Direction   string  `json:"direction"`
	Protocol    string  `json:"protocol"`
	SrcCIDR     *string `json:"src_cidr"`
	DstCIDR     *string `json:"dst_cidr"`
	DstPortFrom *int    `json:"dst_port_from"`
	DstPortTo   *int    `json:"dst_port_to"`
	RatePPS     *int    `json:"rate_pps"`
	Priority    int     `json:"priority"`
	IsActive    bool    `json:"is_active"`
}

func createRule(t *testing.T, e *env, tk string, body gin.H) ruleBody {
	t.Helper()
	w, resp := do(t, e, http.MethodPost, "/api/v1/rules", body, tk)
	if w.Code != http.StatusCreated {
		t.Fatalf("create rule: status=%d body=%s", w.Code, string(resp))
	}
	var out ruleBody
	if err := json.Unmarshal(resp, &out); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, string(resp))
	}
	return out
}

func TestCreateRuleDenyAppliesSyncer(t *testing.T) {
	e := setup(t)
	_, tk := login(t, e, e.email, e.pass)
	e.sync.Reset()

	out := createRule(t, e, tk.AccessToken, gin.H{
		"name":      "block-china-ip",
		"action":    "deny",
		"direction": "ingress",
		"protocol":  "any",
		"src_cidr":  "1.2.3.0/24",
	})

	if out.Action != "deny" || out.IsActive != true {
		t.Errorf("unexpected shape: %+v", out)
	}
	if out.SrcCIDR == nil || *out.SrcCIDR != "1.2.3.0/24" {
		t.Errorf("src_cidr round-trip: got %v", out.SrcCIDR)
	}
	applied, _ := e.sync.Snapshot()
	if len(applied) != 1 || applied[0].ID.String() != out.ID {
		t.Errorf("syncer.Apply not called with new rule: applied=%+v", applied)
	}
}

func TestCreateRuleRateLimitRequiresPPS(t *testing.T) {
	e := setup(t)
	_, tk := login(t, e, e.email, e.pass)
	w, _ := do(t, e, http.MethodPost, "/api/v1/rules", gin.H{
		"name":   "rl-missing-pps",
		"action": "rate_limit",
	}, tk.AccessToken)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestCreateRuleRejectsPPSOnNonRateLimit(t *testing.T) {
	e := setup(t)
	_, tk := login(t, e, e.email, e.pass)
	w, _ := do(t, e, http.MethodPost, "/api/v1/rules", gin.H{
		"name":     "allow-with-pps",
		"action":   "allow",
		"rate_pps": 100,
	}, tk.AccessToken)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestCreateRuleInactiveSkipsSync(t *testing.T) {
	e := setup(t)
	_, tk := login(t, e, e.email, e.pass)
	e.sync.Reset()
	active := false
	_ = createRule(t, e, tk.AccessToken, gin.H{
		"name":      "staged-rule",
		"action":    "deny",
		"is_active": active,
	})
	applied, _ := e.sync.Snapshot()
	if len(applied) != 0 {
		t.Errorf("syncer should not be called for inactive rule: %v", applied)
	}
}

func TestCreateRuleRejectsDuplicateName(t *testing.T) {
	e := setup(t)
	_, tk := login(t, e, e.email, e.pass)
	body := gin.H{"name": "dupname", "action": "deny"}
	_ = createRule(t, e, tk.AccessToken, body)
	w, _ := do(t, e, http.MethodPost, "/api/v1/rules", body, tk.AccessToken)
	if w.Code != http.StatusConflict {
		t.Fatalf("want 409, got %d", w.Code)
	}
}

func TestListRulesReturnsEnvelope(t *testing.T) {
	e := setup(t)
	_, tk := login(t, e, e.email, e.pass)
	_ = createRule(t, e, tk.AccessToken, gin.H{"name": "r1", "action": "deny", "priority": 10})
	_ = createRule(t, e, tk.AccessToken, gin.H{"name": "r2", "action": "allow", "priority": 20})

	w, body := do(t, e, http.MethodGet, "/api/v1/rules?limit=10", nil, tk.AccessToken)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body=%s", w.Code, string(body))
	}
	var resp struct {
		Items []ruleBody `json:"items"`
		Total int        `json:"total"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, string(body))
	}
	if resp.Total < 2 || len(resp.Items) < 2 {
		t.Fatalf("expected ≥2 items, got %+v", resp)
	}
	// Default sort is priority ASC — r1 (priority 10) must come first.
	if resp.Items[0].Name != "r1" {
		t.Errorf("default sort: got %s first, want r1", resp.Items[0].Name)
	}
}

func TestListRulesActiveFilter(t *testing.T) {
	e := setup(t)
	_, tk := login(t, e, e.email, e.pass)
	_ = createRule(t, e, tk.AccessToken, gin.H{"name": "r-on", "action": "deny", "is_active": true})
	_ = createRule(t, e, tk.AccessToken, gin.H{"name": "r-off", "action": "deny", "is_active": false})

	w, body := do(t, e, http.MethodGet, "/api/v1/rules?active=true", nil, tk.AccessToken)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}
	var resp struct {
		Items []ruleBody `json:"items"`
	}
	_ = json.Unmarshal(body, &resp)
	for _, it := range resp.Items {
		if !it.IsActive {
			t.Errorf("active=true returned inactive rule: %s", it.Name)
		}
	}
}

func TestUpdateRulePartialFieldsAndSync(t *testing.T) {
	e := setup(t)
	_, tk := login(t, e, e.email, e.pass)
	created := createRule(t, e, tk.AccessToken, gin.H{
		"name": "to-patch", "action": "deny", "priority": 100,
	})
	e.sync.Reset()

	w, body := do(t, e, http.MethodPatch, "/api/v1/rules/"+created.ID, gin.H{
		"priority": 500,
		"protocol": "tcp",
	}, tk.AccessToken)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body=%s", w.Code, string(body))
	}
	var out ruleBody
	_ = json.Unmarshal(body, &out)
	if out.Priority != 500 || out.Protocol != "tcp" {
		t.Errorf("patch not applied: got %+v", out)
	}
	applied, _ := e.sync.Snapshot()
	if len(applied) != 1 || applied[0].Priority != 500 {
		t.Errorf("syncer not called on update: %v", applied)
	}
}

func TestDeactivateTriggersSyncerDelete(t *testing.T) {
	e := setup(t)
	_, tk := login(t, e, e.email, e.pass)
	created := createRule(t, e, tk.AccessToken, gin.H{"name": "to-off", "action": "deny"})
	e.sync.Reset()

	w, _ := do(t, e, http.MethodPatch, "/api/v1/rules/"+created.ID, gin.H{
		"is_active": false,
	}, tk.AccessToken)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}
	_, deleted := e.sync.Snapshot()
	if len(deleted) != 1 || deleted[0].String() != created.ID {
		t.Errorf("deactivation should call syncer.Delete: %v", deleted)
	}
}

func TestDeleteRuleCascadesToSync(t *testing.T) {
	e := setup(t)
	_, tk := login(t, e, e.email, e.pass)
	created := createRule(t, e, tk.AccessToken, gin.H{"name": "gone", "action": "deny"})
	e.sync.Reset()

	w, _ := do(t, e, http.MethodDelete, "/api/v1/rules/"+created.ID, nil, tk.AccessToken)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status: %d", w.Code)
	}
	_, deleted := e.sync.Snapshot()
	if len(deleted) != 1 {
		t.Errorf("expected one syncer delete, got %v", deleted)
	}

	// Second delete returns 404.
	w, _ = do(t, e, http.MethodDelete, "/api/v1/rules/"+created.ID, nil, tk.AccessToken)
	if w.Code != http.StatusNotFound {
		t.Errorf("second delete: want 404, got %d", w.Code)
	}
}

// seedPeer inserts an interface + peer directly via SQL so binding tests
// don't need the /api/v1/interfaces + /api/v1/peers flows wired into env.
// Returns the peer UUID. Keys are deterministic-but-distinct 32-byte
// payloads so the base64 CHECK constraints pass.
func seedPeer(t *testing.T, e *env) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	ifacePub := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32))
	peerPub := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x02}, 32))
	privStub := bytes.Repeat([]byte{0x03}, 32)

	var ifaceID uuid.UUID
	if err := e.pool.QueryRow(ctx, `
		INSERT INTO wg_interfaces (name, listen_port, address, private_key, public_key)
		VALUES ($1, $2, $3::inet, $4, $5)
		RETURNING id
	`, "wg-rule", 51820, "10.9.0.1/24", privStub, ifacePub).Scan(&ifaceID); err != nil {
		t.Fatalf("seed interface: %v", err)
	}

	var peerID uuid.UUID
	if err := e.pool.QueryRow(ctx, `
		INSERT INTO wg_peers (interface_id, name, public_key, allowed_ips, assigned_ip)
		VALUES ($1, $2, $3, $4::cidr[], $5::inet)
		RETURNING id
	`, ifaceID, "rule-peer", peerPub, []string{"10.9.0.2/32"}, "10.9.0.2").Scan(&peerID); err != nil {
		t.Fatalf("seed peer: %v", err)
	}
	return peerID
}

func TestBindRuleToPeerTriggersResync(t *testing.T) {
	e := setup(t)
	_, tk := login(t, e, e.email, e.pass)
	created := createRule(t, e, tk.AccessToken, gin.H{"name": "bindme", "action": "deny"})

	peerID := seedPeer(t, e)
	e.sync.Reset()

	w, body := do(t, e, http.MethodPost, "/api/v1/rules/"+created.ID+"/bindings", gin.H{
		"peer_id": peerID.String(),
	}, tk.AccessToken)
	if w.Code != http.StatusCreated {
		t.Fatalf("status: %d body=%s", w.Code, string(body))
	}
	applied, _ := e.sync.Snapshot()
	if len(applied) != 1 {
		t.Errorf("bind did not re-apply rule: %v", applied)
	}
}

func TestBindRequiresExactlyOneTarget(t *testing.T) {
	e := setup(t)
	_, tk := login(t, e, e.email, e.pass)
	created := createRule(t, e, tk.AccessToken, gin.H{"name": "bindxor", "action": "deny"})

	cases := []gin.H{
		{}, // neither
		{"peer_id": uuid.New().String(), "interface_id": uuid.New().String()}, // both
	}
	for _, body := range cases {
		w, _ := do(t, e, http.MethodPost, "/api/v1/rules/"+created.ID+"/bindings", body, tk.AccessToken)
		if w.Code != http.StatusBadRequest {
			t.Errorf("body=%v: want 400, got %d", body, w.Code)
		}
	}
}

func TestUpdateRejectsBadEnum(t *testing.T) {
	e := setup(t)
	_, tk := login(t, e, e.email, e.pass)
	created := createRule(t, e, tk.AccessToken, gin.H{"name": "enum-check", "action": "deny"})

	w, _ := do(t, e, http.MethodPatch, "/api/v1/rules/"+created.ID, gin.H{
		"action": "explode",
	}, tk.AccessToken)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestRulesRequireAdminRole(t *testing.T) {
	e := setup(t)
	// Demote and re-login. Copied pattern from users_audit_test.go.
	if _, err := e.pool.Exec(context.Background(),
		`UPDATE users SET role = 'user'::user_role WHERE id = $1`, e.userID); err != nil {
		t.Fatalf("demote: %v", err)
	}
	_, tk := login(t, e, e.email, e.pass)

	w, _ := do(t, e, http.MethodGet, "/api/v1/rules", nil, tk.AccessToken)
	if w.Code != http.StatusForbidden {
		t.Errorf("want 403 for non-admin, got %d", w.Code)
	}
}
