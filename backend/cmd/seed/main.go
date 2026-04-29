// Command seed bootstraps a fresh NexusHub database with an initial
// super_admin user and (optionally) a default WireGuard interface.
//
// It is idempotent: re-running with the same NEXUSHUB_ADMIN_EMAIL updates
// the existing row instead of duplicating it.
//
// Required environment:
//
//	DATABASE_URL              postgres connection string
//	NEXUSHUB_ADMIN_EMAIL      email for the initial super_admin
//	NEXUSHUB_ADMIN_USERNAME   username for the initial super_admin
//	NEXUSHUB_ADMIN_PASSWORD   plaintext password — hashed on insert, never stored
//
// Optional environment:
//
//	NEXUSHUB_SEED_WG=1        also create the default wg0 interface
//	WG_INTERFACE              defaults to wg0
//	WG_LISTEN_PORT            defaults to 51820
//	WG_ADDRESS                defaults to 10.8.0.1/24
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/curve25519"

	"github.com/tomeksdev/NexusHub/backend/internal/auth"
	"github.com/tomeksdev/NexusHub/backend/internal/db"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx); err != nil {
		slog.Error("seed failed", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is not set")
	}

	adminEmail := os.Getenv("NEXUSHUB_ADMIN_EMAIL")
	adminUsername := os.Getenv("NEXUSHUB_ADMIN_USERNAME")
	adminPassword := os.Getenv("NEXUSHUB_ADMIN_PASSWORD")
	if adminEmail == "" || adminUsername == "" || adminPassword == "" {
		return errors.New("NEXUSHUB_ADMIN_EMAIL, NEXUSHUB_ADMIN_USERNAME and NEXUSHUB_ADMIN_PASSWORD must all be set")
	}

	pool, err := db.NewPool(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	if err := seedAdmin(ctx, pool, adminEmail, adminUsername, adminPassword); err != nil {
		return fmt.Errorf("seed admin: %w", err)
	}

	if os.Getenv("NEXUSHUB_SEED_WG") == "1" {
		if err := seedInterface(ctx, pool); err != nil {
			return fmt.Errorf("seed interface: %w", err)
		}
	}

	slog.Info("seed complete")
	return nil
}

func seedAdmin(ctx context.Context, pool *pgxpool.Pool, email, username, password string) error {
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}

	const q = `
        INSERT INTO users (email, username, password_hash, role, is_active)
        VALUES ($1, $2, $3, 'super_admin', TRUE)
        ON CONFLICT (email) DO UPDATE
           SET username      = EXCLUDED.username,
               password_hash = EXCLUDED.password_hash,
               role          = 'super_admin',
               is_active     = TRUE
        RETURNING id
    `

	var id string
	if err := pool.QueryRow(ctx, q, email, username, hash).Scan(&id); err != nil {
		return err
	}
	slog.Info("admin user seeded", "id", id, "email", email)
	return nil
}

func seedInterface(ctx context.Context, pool *pgxpool.Pool) error {
	name := envOr("WG_INTERFACE", "wg0")
	port, err := strconv.Atoi(envOr("WG_LISTEN_PORT", "51820"))
	if err != nil {
		return fmt.Errorf("WG_LISTEN_PORT: %w", err)
	}
	address := envOr("WG_ADDRESS", "10.8.0.1/24")

	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM wg_interfaces WHERE name = $1)`, name).Scan(&exists); err != nil {
		return err
	}
	if exists {
		slog.Info("interface already seeded; skipping", "name", name)
		return nil
	}

	priv, pub, err := generateWGKeypair()
	if err != nil {
		return err
	}

	const q = `
        INSERT INTO wg_interfaces (name, listen_port, address, private_key, public_key)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id
    `

	// TODO(phase-4): encrypt private_key at rest using PEER_KEY_ENCRYPTION_KEY
	// before inserting. Seeding in plaintext is acceptable only until the
	// crypto helper lands; the private key never leaves the database.
	var id string
	if err := pool.QueryRow(ctx, q, name, port, address, priv, pub).Scan(&id); err != nil {
		return err
	}
	slog.Info("interface seeded", "id", id, "name", name, "listen_port", port, "address", address)
	return nil
}

func generateWGKeypair() (priv []byte, pub string, err error) {
	var privArr [curve25519.ScalarSize]byte
	if _, err := rand.Read(privArr[:]); err != nil {
		return nil, "", fmt.Errorf("read random: %w", err)
	}
	// Curve25519 key clamping per RFC 7748 §5.
	privArr[0] &= 248
	privArr[31] &= 127
	privArr[31] |= 64

	pubBytes, err := curve25519.X25519(privArr[:], curve25519.Basepoint)
	if err != nil {
		return nil, "", fmt.Errorf("derive public key: %w", err)
	}

	return privArr[:], base64.StdEncoding.EncodeToString(pubBytes), nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
