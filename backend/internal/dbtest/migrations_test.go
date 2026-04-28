//go:build integration
// +build integration

package dbtest_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tomeksdev/NexusHub/backend/internal/dbtest"
)

// TestMigrationsRoundTrip applies every migration up, rolls them all back,
// and re-applies them. This catches broken down migrations and non-idempotent
// ups that would hide when only the up path is exercised.
func TestMigrationsRoundTrip(t *testing.T) {
	adminDSN := dbtest.AdminDSN(t)

	ctx := context.Background()
	admin, err := pgxpool.New(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	defer admin.Close()

	dbName := "migrations_roundtrip"
	// Ensure a clean slate even if a prior run crashed mid-test.
	_, _ = admin.Exec(ctx,
		`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1`, dbName)
	_, _ = admin.Exec(ctx, fmt.Sprintf(`DROP DATABASE IF EXISTS %s`, dbName))
	if _, err := admin.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s`, dbName)); err != nil {
		t.Fatalf("create db: %v", err)
	}
	t.Cleanup(func() {
		drop, err := pgxpool.New(context.Background(), adminDSN)
		if err != nil {
			return
		}
		defer drop.Close()
		_, _ = drop.Exec(context.Background(),
			`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1`, dbName)
		_, _ = drop.Exec(context.Background(), fmt.Sprintf(`DROP DATABASE IF EXISTS %s`, dbName))
	})

	m, err := dbtest.NewMigrator(dbtest.DSNFor(t, dbName))
	if err != nil {
		t.Fatalf("new migrator: %v", err)
	}
	t.Cleanup(func() { _, _ = m.Close() })

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("first up: %v", err)
	}
	topVersion, _, err := m.Version()
	if err != nil {
		t.Fatalf("version after first up: %v", err)
	}

	if err := m.Down(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("down: %v", err)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("second up: %v", err)
	}
	secondVersion, _, err := m.Version()
	if err != nil {
		t.Fatalf("version after second up: %v", err)
	}

	if topVersion != secondVersion {
		t.Fatalf("version mismatch after round-trip: got %d, want %d", secondVersion, topVersion)
	}
}

// TestFreshAppliesAllMigrations sanity-checks that a Fresh() database has
// every expected table. If a migration is silently skipped, this catches it.
func TestFreshAppliesAllMigrations(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()

	expected := []string{
		"users", "sessions", "refresh_tokens",
		"wg_interfaces", "wg_peers", "wg_peer_preshared_keys",
		"ebpf_rules", "ebpf_rule_bindings",
		"audit_log",
		"api_keys",
		"connection_logs", "connection_logs_default",
	}

	for _, table := range expected {
		var exists bool
		err := pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)`,
			table,
		).Scan(&exists)
		if err != nil {
			t.Fatalf("lookup %s: %v", table, err)
		}
		if !exists {
			t.Errorf("table %s missing after migrations", table)
		}
	}
}
