//go:build integration
// +build integration

package repository_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/tomeksdev/NexusHub/backend/internal/dbtest"
	"github.com/tomeksdev/NexusHub/backend/internal/repository"
)

// TestAuditPruneOlderThan exercises the real DELETE path against a
// freshly-migrated database. Seeds three rows at different offsets
// from the cutoff and verifies the delete keeps only what's newer.
func TestAuditPruneOlderThan(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	repo := repository.NewAuditRepo(pool)

	// occurred_at defaults to now(); we force timestamps via an UPDATE
	// afterwards so the test doesn't depend on clock skew.
	seed := func(action string, occurredAt time.Time) {
		if err := repo.LogStrict(ctx, repository.AuditEntry{
			Action:     action,
			TargetType: "test",
			TargetID:   "seed",
			ActorIP:    net.ParseIP("127.0.0.1"),
			Result:     repository.AuditResultSuccess,
		}); err != nil {
			t.Fatalf("seed %q: %v", action, err)
		}
		if _, err := pool.Exec(ctx,
			`UPDATE audit_log SET occurred_at = $1 WHERE action = $2`,
			occurredAt, action); err != nil {
			t.Fatalf("backdate %q: %v", action, err)
		}
	}

	now := time.Now()
	seed("ancient", now.Add(-30*24*time.Hour))
	seed("stale", now.Add(-7*24*time.Hour))
	seed("fresh", now.Add(-1*time.Hour))

	// Cutoff = 14 days ago. Only "ancient" is older; "stale" and
	// "fresh" must survive.
	cutoff := now.Add(-14 * 24 * time.Hour)
	removed, err := repo.PruneOlderThan(ctx, cutoff)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 2 {
		t.Fatalf("survivors = %d, want 2", count)
	}

	// Running the prune again with the same cutoff is a no-op.
	removed, err = repo.PruneOlderThan(ctx, cutoff)
	if err != nil {
		t.Fatalf("second prune: %v", err)
	}
	if removed != 0 {
		t.Fatalf("idempotent prune removed = %d, want 0", removed)
	}
}
