// Package dbtest spins up a real PostgreSQL container for integration tests.
//
// Per Phase 2 plan in TODO.md: "Unit tests using a real Postgres (no mocks)".
// Tests share one container across the package for speed; each test that
// needs isolation calls Fresh(t) to get its own database within that
// container.
package dbtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	containerImage = "postgres:16-alpine"
	dbUser         = "nexushub"
	dbPassword     = "nexushub"
	templateDBName = "nexushub_template"
	startupTimeout = 90 * time.Second
)

// sharedContainer is a lazily-started postgres container reused by every
// test in a package. We migrate the template database once and then
// CREATE DATABASE ... TEMPLATE nexushub_template for each call to Fresh,
// which is faster than re-running migrations per test.
type sharedContainer struct {
	once      sync.Once
	err       error
	container *postgres.PostgresContainer
	adminDSN  string // points at the "postgres" maintenance DB
	host      string
	port      string
}

var shared = &sharedContainer{}

// Fresh returns a pgxpool.Pool wired to an isolated database that has been
// migrated to the latest schema. The database is dropped when the test ends.
func Fresh(t *testing.T) *pgxpool.Pool {
	t.Helper()
	shared.once.Do(shared.start)
	if shared.err != nil {
		t.Fatalf("start shared postgres: %v", shared.err)
	}

	ctx := context.Background()
	name := "test_" + randomSuffix(t)

	admin, err := pgxpool.New(ctx, shared.adminDSN)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	defer admin.Close()

	if _, err := admin.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s TEMPLATE %s`, name, templateDBName)); err != nil {
		t.Fatalf("create per-test db: %v", err)
	}

	dsn := buildDSN(shared.host, shared.port, name)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect per-test db: %v", err)
	}

	t.Cleanup(func() {
		pool.Close()
		drop, err := pgxpool.New(context.Background(), shared.adminDSN)
		if err != nil {
			t.Logf("drop connect: %v", err)
			return
		}
		defer drop.Close()
		// Terminate any leftover sessions so DROP DATABASE won't block.
		_, _ = drop.Exec(context.Background(),
			`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1`, name)
		if _, err := drop.Exec(context.Background(), fmt.Sprintf(`DROP DATABASE IF EXISTS %s`, name)); err != nil {
			t.Logf("drop db %s: %v", name, err)
		}
	})

	return pool
}

// MigrationsPath returns the absolute path to the repo's migrations/ dir,
// resolved relative to this source file. Exported so migration-specific
// tests can load golang-migrate directly.
func MigrationsPath() string {
	_, thisFile, _, _ := runtime.Caller(0)
	// backend/internal/dbtest/dbtest.go → ../../../migrations
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "migrations")
}

// AdminDSN returns the DSN to the shared container's maintenance database.
// Useful for tests that need to observe cluster-level state.
func AdminDSN(t *testing.T) string {
	t.Helper()
	shared.once.Do(shared.start)
	if shared.err != nil {
		t.Fatalf("start shared postgres: %v", shared.err)
	}
	return shared.adminDSN
}

// DSNFor returns a connection string for a named database on the shared
// container. The database itself is not created — the caller is responsible
// for CREATE DATABASE (typically against AdminDSN).
func DSNFor(t *testing.T, dbName string) string {
	t.Helper()
	shared.once.Do(shared.start)
	if shared.err != nil {
		t.Fatalf("start shared postgres: %v", shared.err)
	}
	return buildDSN(shared.host, shared.port, dbName)
}

func (s *sharedContainer) start() {
	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()

	container, err := postgres.RunContainer(ctx,
		testcontainers.WithImage(containerImage),
		postgres.WithDatabase("postgres"),
		postgres.WithUsername(dbUser),
		postgres.WithPassword(dbPassword),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(startupTimeout),
		),
	)
	if err != nil {
		s.err = fmt.Errorf("run container: %w", err)
		return
	}
	s.container = container

	host, err := container.Host(ctx)
	if err != nil {
		s.err = fmt.Errorf("host: %w", err)
		return
	}
	port, err := container.MappedPort(ctx, "5432/tcp")
	if err != nil {
		s.err = fmt.Errorf("mapped port: %w", err)
		return
	}
	s.host = host
	s.port = port.Port()
	s.adminDSN = buildDSN(s.host, s.port, "postgres")

	// Build the template database and migrate it once.
	admin, err := pgxpool.New(ctx, s.adminDSN)
	if err != nil {
		s.err = fmt.Errorf("connect admin: %w", err)
		return
	}
	defer admin.Close()

	if _, err := admin.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s`, templateDBName)); err != nil {
		s.err = fmt.Errorf("create template db: %w", err)
		return
	}

	templateDSN := buildDSN(s.host, s.port, templateDBName)
	if err := RunMigrations(templateDSN); err != nil {
		s.err = fmt.Errorf("migrate template: %w", err)
		return
	}

	// Mark template so CREATE DATABASE ... TEMPLATE works and prevent
	// accidental writes to it.
	if _, err := admin.Exec(ctx, fmt.Sprintf(`ALTER DATABASE %s IS_TEMPLATE true`, templateDBName)); err != nil {
		s.err = fmt.Errorf("mark template: %w", err)
		return
	}
}

// RunMigrations applies every migration in MigrationsPath() against dsn.
// Exported so the round-trip test can drive migrations directly.
func RunMigrations(dsn string) error {
	m, err := migrate.New("file://"+MigrationsPath(), dsn)
	if err != nil {
		return fmt.Errorf("open migrator: %w", err)
	}
	defer m.Close()
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}

// NewMigrator returns a raw *migrate.Migrate for advanced tests that need
// explicit Down/Up control. Caller must Close() it.
func NewMigrator(dsn string) (*migrate.Migrate, error) {
	return migrate.New("file://"+MigrationsPath(), dsn)
}

func buildDSN(host, port, dbName string) string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		dbUser, dbPassword, host, port, dbName)
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return strings.ToLower(hex.EncodeToString(b[:]))
}
