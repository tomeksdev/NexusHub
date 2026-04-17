//go:build integration
// +build integration

package dbtest_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/dbtest"
)

const validPubKey = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ=" // 43 + '='

func TestUsersConstraints(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()

	// Email is CITEXT — mixed case must conflict with lowercase.
	insertUser(t, pool, "Admin@Example.com", "admin", "user")
	if err := rawInsertUser(ctx, pool, "admin@example.com", "admin2", "user"); err == nil {
		t.Error("expected case-insensitive email uniqueness, got no error")
	} else if !isUniqueViolation(err) {
		t.Errorf("expected unique violation, got: %v", err)
	}

	// Username must match the format regex.
	if err := rawInsertUser(ctx, pool, "bad@example.com", "no spaces here", "user"); err == nil {
		t.Error("expected username format violation for value with spaces")
	}

	// Unknown role is rejected by the enum.
	if err := rawInsertUser(ctx, pool, "role@example.com", "roleuser", "hacker"); err == nil {
		t.Error("expected enum violation for unknown role")
	}
}

func TestRefreshTokenHashLength(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()

	userID := insertUser(t, pool, "rt@example.com", "rt_user", "user")
	var sessionID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO sessions (user_id) VALUES ($1) RETURNING id`, userID,
	).Scan(&sessionID); err != nil {
		t.Fatalf("insert session: %v", err)
	}

	expires := time.Now().Add(7 * 24 * time.Hour)

	// 16-byte hash: must fail the length check (requires 32).
	_, err := pool.Exec(ctx,
		`INSERT INTO refresh_tokens (session_id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)`,
		sessionID, userID, make([]byte, 16), expires,
	)
	if err == nil {
		t.Error("expected CHECK violation on 16-byte token_hash")
	}

	// 32-byte hash succeeds.
	if _, err := pool.Exec(ctx,
		`INSERT INTO refresh_tokens (session_id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)`,
		sessionID, userID, make([]byte, 32), expires,
	); err != nil {
		t.Errorf("valid 32-byte hash rejected: %v", err)
	}
}

func TestWGPeerPublicKeyFormat(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()

	ifaceID := insertInterface(t, pool)

	// Bad public key (wrong length) rejected.
	_, err := pool.Exec(ctx,
		`INSERT INTO wg_peers (interface_id, name, public_key, assigned_ip)
		 VALUES ($1, $2, $3, $4)`,
		ifaceID, "peer-bad", "tooshort==", "10.8.0.2",
	)
	if err == nil {
		t.Error("expected pubkey format CHECK violation")
	}

	// Valid peer.
	if _, err := pool.Exec(ctx,
		`INSERT INTO wg_peers (interface_id, name, public_key, assigned_ip)
		 VALUES ($1, $2, $3, $4)`,
		ifaceID, "peer-ok", validPubKey, "10.8.0.2",
	); err != nil {
		t.Fatalf("valid peer rejected: %v", err)
	}

	// Duplicate public key across peers is rejected by the UNIQUE constraint.
	if _, err := pool.Exec(ctx,
		`INSERT INTO wg_peers (interface_id, name, public_key, assigned_ip)
		 VALUES ($1, $2, $3, $4)`,
		ifaceID, "peer-dupkey", validPubKey, "10.8.0.3",
	); err == nil || !isUniqueViolation(err) {
		t.Errorf("expected unique violation on duplicate public_key, got: %v", err)
	}

	// Duplicate assigned_ip within the same interface is rejected.
	otherKey := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	if _, err := pool.Exec(ctx,
		`INSERT INTO wg_peers (interface_id, name, public_key, assigned_ip)
		 VALUES ($1, $2, $3, $4)`,
		ifaceID, "peer-dupip", otherKey, "10.8.0.2",
	); err == nil || !isUniqueViolation(err) {
		t.Errorf("expected unique violation on duplicate assigned_ip, got: %v", err)
	}
}

func TestInterfaceDeleteCascadesToPeers(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()

	ifaceID := insertInterface(t, pool)
	if _, err := pool.Exec(ctx,
		`INSERT INTO wg_peers (interface_id, name, public_key, assigned_ip)
		 VALUES ($1, $2, $3, $4)`,
		ifaceID, "cascader", validPubKey, "10.8.0.9",
	); err != nil {
		t.Fatalf("insert peer: %v", err)
	}

	if _, err := pool.Exec(ctx, `DELETE FROM wg_interfaces WHERE id = $1`, ifaceID); err != nil {
		t.Fatalf("delete interface: %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM wg_peers WHERE interface_id = $1`, ifaceID,
	).Scan(&count); err != nil {
		t.Fatalf("count peers: %v", err)
	}
	if count != 0 {
		t.Errorf("expected cascade to remove peers, found %d", count)
	}
}

func TestEBPFRuleBindingXOR(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()

	var ruleID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO ebpf_rules (name, action) VALUES ('deny-all', 'deny') RETURNING id`,
	).Scan(&ruleID); err != nil {
		t.Fatalf("insert rule: %v", err)
	}

	// Neither target set — must fail.
	if _, err := pool.Exec(ctx,
		`INSERT INTO ebpf_rule_bindings (rule_id) VALUES ($1)`, ruleID,
	); err == nil {
		t.Error("expected XOR violation when neither peer nor interface set")
	}

	ifaceID := insertInterface(t, pool)
	var peerID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO wg_peers (interface_id, name, public_key, assigned_ip)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		ifaceID, "bind-peer", validPubKey, "10.8.0.20",
	).Scan(&peerID); err != nil {
		t.Fatalf("insert peer: %v", err)
	}

	// Both targets set — must fail.
	if _, err := pool.Exec(ctx,
		`INSERT INTO ebpf_rule_bindings (rule_id, peer_id, interface_id) VALUES ($1, $2, $3)`,
		ruleID, peerID, ifaceID,
	); err == nil {
		t.Error("expected XOR violation when both targets set")
	}

	// Exactly one — succeeds.
	if _, err := pool.Exec(ctx,
		`INSERT INTO ebpf_rule_bindings (rule_id, peer_id) VALUES ($1, $2)`, ruleID, peerID,
	); err != nil {
		t.Errorf("valid binding rejected: %v", err)
	}
}

func TestConnectionLogsRouteToMonthlyPartition(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()

	// Insert a row at "now" — the seeded current-month partition must absorb it.
	if _, err := pool.Exec(ctx,
		`INSERT INTO connection_logs (src_ip, bytes_in) VALUES ($1, $2)`,
		"10.0.0.1", int64(42),
	); err != nil {
		t.Fatalf("insert current-month row: %v", err)
	}

	// Confirm the row did NOT land in the default partition — that would mean
	// the monthly partitions weren't seeded correctly.
	var defaultCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM connection_logs_default`,
	).Scan(&defaultCount); err != nil {
		t.Fatalf("count default partition: %v", err)
	}
	if defaultCount != 0 {
		t.Errorf("row fell into default partition; monthly partition missing for current month")
	}

	// A row far in the past has no monthly partition seeded → default absorbs it.
	if _, err := pool.Exec(ctx,
		`INSERT INTO connection_logs (recorded_at, src_ip) VALUES ($1, $2)`,
		time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC), "10.0.0.2",
	); err != nil {
		t.Fatalf("insert ancient row: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM connection_logs_default`,
	).Scan(&defaultCount); err != nil {
		t.Fatalf("count default partition (2): %v", err)
	}
	if defaultCount != 1 {
		t.Errorf("expected ancient row in default partition, got count=%d", defaultCount)
	}
}

func TestCreateConnectionLogsPartitionIdempotent(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()

	target := time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 2; i++ {
		if _, err := pool.Exec(ctx,
			`SELECT create_connection_logs_partition($1::date)`, target,
		); err != nil {
			t.Fatalf("call #%d: %v", i+1, err)
		}
	}

	var exists bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'connection_logs_2030_06')`,
	).Scan(&exists); err != nil {
		t.Fatalf("lookup partition: %v", err)
	}
	if !exists {
		t.Error("expected connection_logs_2030_06 to exist")
	}
}

func TestUpdatedAtTriggerFires(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()

	id := insertUser(t, pool, "trig@example.com", "trig_user", "user")

	var before, after time.Time
	if err := pool.QueryRow(ctx, `SELECT updated_at FROM users WHERE id = $1`, id).Scan(&before); err != nil {
		t.Fatalf("read before: %v", err)
	}

	// Sleep 10ms to guarantee a distinct timestamp even on fast clocks.
	time.Sleep(10 * time.Millisecond)

	if _, err := pool.Exec(ctx, `UPDATE users SET username = 'trig_user2' WHERE id = $1`, id); err != nil {
		t.Fatalf("update: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT updated_at FROM users WHERE id = $1`, id).Scan(&after); err != nil {
		t.Fatalf("read after: %v", err)
	}

	if !after.After(before) {
		t.Errorf("updated_at trigger did not fire: before=%s after=%s", before, after)
	}
}

func insertUser(t *testing.T, pool *pgxpool.Pool, email, username, role string) string {
	t.Helper()
	var id string
	const q = `INSERT INTO users (email, username, password_hash, role)
	           VALUES ($1, $2, $3, $4::user_role) RETURNING id`
	if err := pool.QueryRow(context.Background(), q, email, username, "x", role).Scan(&id); err != nil {
		t.Fatalf("insert user %s: %v", email, err)
	}
	return id
}

func rawInsertUser(ctx context.Context, pool *pgxpool.Pool, email, username, role string) error {
	const q = `INSERT INTO users (email, username, password_hash, role)
	           VALUES ($1, $2, $3, $4::user_role)`
	_, err := pool.Exec(ctx, q, email, username, "x", role)
	return err
}

func insertInterface(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var id string
	const q = `INSERT INTO wg_interfaces (name, listen_port, address, private_key, public_key)
	           VALUES ($1, $2, $3, $4, $5) RETURNING id`
	if err := pool.QueryRow(context.Background(), q,
		"wg0", 51820, "10.8.0.1/24", []byte("privkey"), validPubKey,
	).Scan(&id); err != nil {
		t.Fatalf("insert interface: %v", err)
	}
	return id
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	// pgx surfaces PgError with SQLSTATE 23505 for unique_violation. We match
	// on the string to avoid importing pgconn in tests.
	var target interface{ SQLState() string }
	if errors.As(err, &target) {
		return target.SQLState() == "23505"
	}
	return strings.Contains(err.Error(), "23505") || strings.Contains(err.Error(), "duplicate key")
}
