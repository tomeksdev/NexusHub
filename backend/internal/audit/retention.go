// Package audit owns the retention loop for audit_log rows.
//
// The repository exposes PruneOlderThan(cutoff); this package runs it
// on a ticker and is the only thing main.go needs to kick off to get
// automatic pruning. Kept separate so the repository stays focused on
// reads/writes and can be used from other contexts (tests, CLI tools)
// without dragging a goroutine along.
package audit

import (
	"context"
	"log/slog"
	"time"
)

// Pruner is the small surface this loop needs from the audit
// repository. Declared here so tests can stub it — we never touch a
// real DB in unit tests for the loop.
type Pruner interface {
	PruneOlderThan(ctx context.Context, cutoff time.Time) (int64, error)
}

// RetentionConfig controls the loop cadence and the age cutoff.
// Zero Retention disables the loop entirely so operators who want
// indefinite retention (or who prune out-of-band) can opt out via
// env without special-casing in wiring code.
type RetentionConfig struct {
	// Retention is the maximum age of a row kept in the table.
	// Zero disables pruning.
	Retention time.Duration

	// Interval is how often the loop runs. Defaults to 1h when zero;
	// tests pass shorter values.
	Interval time.Duration

	// Now overrides time.Now for tests. Production leaves it nil.
	Now func() time.Time
}

// RunRetentionLoop blocks until ctx is cancelled, running one prune
// pass per Interval. Each pass deletes rows older than
// Now() - Retention. Errors are logged and swallowed — a transient
// DB hiccup shouldn't bring the API down, and the next tick will
// try again.
//
// Intended use:
//
//	go audit.RunRetentionLoop(ctx, auditRepo, audit.RetentionConfig{
//	    Retention: 90 * 24 * time.Hour,
//	}, logger)
func RunRetentionLoop(ctx context.Context, p Pruner, cfg RetentionConfig, logger *slog.Logger) {
	if cfg.Retention <= 0 {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = time.Hour
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	// Run one pass immediately so an operator starting the service
	// after a retention-bump gets convergence without waiting for
	// the first tick.
	runOnce(ctx, p, cfg.Retention, now(), logger)

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			runOnce(ctx, p, cfg.Retention, now(), logger)
		}
	}
}

func runOnce(ctx context.Context, p Pruner, retention time.Duration, now time.Time, logger *slog.Logger) {
	cutoff := now.Add(-retention)
	n, err := p.PruneOlderThan(ctx, cutoff)
	if err != nil {
		logger.Warn("audit retention prune", "err", err, "cutoff", cutoff)
		return
	}
	if n > 0 {
		logger.Info("audit retention pruned", "rows", n, "cutoff", cutoff)
	}
}
