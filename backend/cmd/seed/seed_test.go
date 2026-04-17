//go:build integration
// +build integration

package main

import (
	"context"
	"testing"

	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/auth"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/dbtest"
)

func TestSeedAdminCreatesSuperAdmin(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()

	if err := seedAdmin(ctx, pool, "root@example.com", "root", "correct-horse-battery-staple"); err != nil {
		t.Fatalf("seedAdmin: %v", err)
	}

	var (
		role     string
		active   bool
		hash     string
		username string
	)
	if err := pool.QueryRow(ctx,
		`SELECT role::text, is_active, password_hash, username
		   FROM users WHERE email = 'root@example.com'`,
	).Scan(&role, &active, &hash, &username); err != nil {
		t.Fatalf("select seeded user: %v", err)
	}

	if role != "super_admin" {
		t.Errorf("role: got %q, want super_admin", role)
	}
	if !active {
		t.Error("seeded user should be active")
	}
	if username != "root" {
		t.Errorf("username: got %q, want root", username)
	}

	ok, err := auth.VerifyPassword("correct-horse-battery-staple", hash)
	if err != nil {
		t.Fatalf("verify hash: %v", err)
	}
	if !ok {
		t.Error("stored password hash did not verify against plaintext")
	}
}

func TestSeedAdminIsIdempotent(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()

	if err := seedAdmin(ctx, pool, "idem@example.com", "orig", "pw1"); err != nil {
		t.Fatalf("first seed: %v", err)
	}
	if err := seedAdmin(ctx, pool, "idem@example.com", "updated", "pw2"); err != nil {
		t.Fatalf("second seed: %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE email = 'idem@example.com'`,
	).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("expected idempotent upsert, got %d rows", count)
	}

	// Latest call's username and password should win.
	var username, hash string
	if err := pool.QueryRow(ctx,
		`SELECT username, password_hash FROM users WHERE email = 'idem@example.com'`,
	).Scan(&username, &hash); err != nil {
		t.Fatalf("select: %v", err)
	}
	if username != "updated" {
		t.Errorf("username: got %q, want updated", username)
	}
	ok, err := auth.VerifyPassword("pw2", hash)
	if err != nil || !ok {
		t.Errorf("expected pw2 to verify, got ok=%v err=%v", ok, err)
	}
}

func TestSeedInterfaceCreatesAndSkipsExisting(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()

	t.Setenv("WG_INTERFACE", "wg0")
	t.Setenv("WG_LISTEN_PORT", "51820")
	t.Setenv("WG_ADDRESS", "10.8.0.1/24")

	if err := seedInterface(ctx, pool); err != nil {
		t.Fatalf("first seedInterface: %v", err)
	}

	var pubBefore string
	if err := pool.QueryRow(ctx,
		`SELECT public_key FROM wg_interfaces WHERE name = 'wg0'`,
	).Scan(&pubBefore); err != nil {
		t.Fatalf("select public_key: %v", err)
	}

	// Second call must skip — not rotate the existing keypair.
	if err := seedInterface(ctx, pool); err != nil {
		t.Fatalf("second seedInterface: %v", err)
	}

	var pubAfter string
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*), max(public_key) FROM wg_interfaces WHERE name = 'wg0'`,
	).Scan(&count, &pubAfter); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 interface row, got %d", count)
	}
	if pubBefore != pubAfter {
		t.Errorf("public_key rotated on second call: before=%q after=%q", pubBefore, pubAfter)
	}
}

func TestGenerateWGKeypairProducesValidFormat(t *testing.T) {
	priv, pub, err := generateWGKeypair()
	if err != nil {
		t.Fatalf("generateWGKeypair: %v", err)
	}
	if len(priv) != 32 {
		t.Errorf("private key length: got %d, want 32", len(priv))
	}
	if len(pub) != 44 {
		t.Errorf("public key length: got %d, want 44", len(pub))
	}
	if pub[43] != '=' {
		t.Errorf("public key should end with '=': got %q", pub)
	}
}
