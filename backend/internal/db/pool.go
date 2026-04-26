// Package db wires pgxpool into the rest of the backend.
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tomeksdev/NexusHub/backend/internal/tracing"
)

const (
	maxConns        = 25
	minConns        = 2
	maxConnLifetime = time.Hour
	maxConnIdleTime = 30 * time.Minute
	connectTimeout  = 10 * time.Second
)

func NewPool(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}

	cfg.MaxConns = maxConns
	cfg.MinConns = minConns
	cfg.MaxConnLifetime = maxConnLifetime
	cfg.MaxConnIdleTime = maxConnIdleTime
	cfg.ConnConfig.ConnectTimeout = connectTimeout
	// Emit one OTEL span per query. When tracing is disabled (no OTEL
	// endpoint configured), the tracer resolves to noop and the hook
	// is effectively free.
	cfg.ConnConfig.Tracer = tracing.NewPgxTracer()

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pgx pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return pool, nil
}
