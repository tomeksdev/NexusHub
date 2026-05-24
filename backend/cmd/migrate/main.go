// Command migrate is a thin wrapper around golang-migrate that reads the
// database URL from the environment and operates on ../../migrations.
//
// Usage:
//
//	migrate up                 apply all pending migrations
//	migrate down               roll back every migration (DESTRUCTIVE)
//	migrate down N             roll back N migrations
//	migrate goto V             migrate forwards or backwards to version V
//	migrate version            print current schema version
//	migrate force V            mark the database as version V (clears dirty flag)
//	migrate drop               drop everything in the database (DESTRUCTIVE)
//	migrate create NAME        create a new NNN_NAME.up/down.sql pair
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	migrationsPath := fs.String("path", defaultMigrationsPath(), "path to migrations directory")
	fs.Usage = usage(fs)

	if len(os.Args) < 2 {
		fs.Usage()
		os.Exit(2)
	}

	// Pre-walk argv so `-path` works regardless of position. Go's
	// stdlib flag package stops parsing at the first non-flag arg,
	// which means `migrate force 8 -path /opt/...` would silently
	// drop the path flag and fall back to defaultMigrationsPath().
	// That bit operators in production with an opaque "open .: no
	// such file or directory" error.
	pathOverride, rest := extractStringFlag(os.Args[1:], "-path", "--path")
	if err := fs.Parse(rest); err != nil {
		os.Exit(2)
	}
	if pathOverride != "" {
		*migrationsPath = pathOverride
	}
	posArgs := fs.Args()
	if len(posArgs) < 1 {
		fs.Usage()
		os.Exit(2)
	}
	cmd := posArgs[0]
	args := posArgs[1:]

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" && cmd != "create" {
		slog.Error("DATABASE_URL is not set")
		os.Exit(1)
	}

	if cmd == "create" {
		if len(args) != 1 {
			slog.Error("create requires a migration name", "example", "migrate create add_users_table")
			os.Exit(2)
		}
		if err := createMigration(*migrationsPath, args[0]); err != nil {
			slog.Error("create migration failed", "err", err)
			os.Exit(1)
		}
		return
	}

	sourceURL := "file://" + *migrationsPath
	m, err := migrate.New(sourceURL, databaseURL)
	if err != nil {
		slog.Error("open migrator", "err", err)
		os.Exit(1)
	}
	defer func() {
		sErr, dErr := m.Close()
		if sErr != nil {
			slog.Warn("close source", "err", sErr)
		}
		if dErr != nil {
			slog.Warn("close database", "err", dErr)
		}
	}()

	if err := run(m, cmd, args); err != nil {
		slog.Error("migration command failed", "cmd", cmd, "err", err)
		os.Exit(1)
	}
}

func run(m *migrate.Migrate, cmd string, args []string) error {
	switch cmd {
	case "up":
		return handleNoChange(m.Up())
	case "down":
		if len(args) == 0 {
			return handleNoChange(m.Down())
		}
		n, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("down argument must be an integer: %w", err)
		}
		return handleNoChange(m.Steps(-n))
	case "goto":
		if len(args) != 1 {
			return errors.New("goto requires a target version")
		}
		// Bitsize matches strconv.IntSize so we can't widen past `uint`
		// when converting — silences CodeQL's incorrect-integer-conversion
		// warning and rejects out-of-range version numbers up front.
		v, err := strconv.ParseUint(args[0], 10, strconv.IntSize)
		if err != nil {
			return fmt.Errorf("goto version must be an unsigned integer: %w", err)
		}
		return handleNoChange(m.Migrate(uint(v)))
	case "version":
		v, dirty, err := m.Version()
		if errors.Is(err, migrate.ErrNilVersion) {
			fmt.Println("no migrations applied")
			return nil
		}
		if err != nil {
			return err
		}
		fmt.Printf("version=%d dirty=%v\n", v, dirty)
		return nil
	case "force":
		if len(args) != 1 {
			return errors.New("force requires a version")
		}
		v, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("force version must be an integer: %w", err)
		}
		return m.Force(v)
	case "drop":
		return m.Drop()
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

// extractStringFlag pulls a string flag out of argv regardless of where
// it appears, accepting `-name X`, `--name X`, `-name=X`, `--name=X`.
// Returns the value (empty string if absent) and the remaining argv
// with the flag tokens removed. Last occurrence wins so callers can
// override an env-default by appending the flag at the end.
func extractStringFlag(argv []string, names ...string) (string, []string) {
	prefixes := make([]string, 0, len(names)*2)
	for _, n := range names {
		prefixes = append(prefixes, n+"=")
	}
	value := ""
	rest := make([]string, 0, len(argv))
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		matched := false
		for _, n := range names {
			if a == n {
				if i+1 < len(argv) {
					value = argv[i+1]
					i++
				}
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		for _, p := range prefixes {
			if strings.HasPrefix(a, p) {
				value = strings.TrimPrefix(a, p)
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		rest = append(rest, a)
	}
	return value, rest
}

func handleNoChange(err error) error {
	if errors.Is(err, migrate.ErrNoChange) {
		slog.Info("no change")
		return nil
	}
	return err
}

func defaultMigrationsPath() string {
	// backend/cmd/migrate → ../../../migrations
	if wd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(wd, "..", "..", "..", "migrations")
		if _, err := os.Stat(candidate); err == nil {
			abs, _ := filepath.Abs(candidate)
			return abs
		}
	}
	return "migrations"
}

func createMigration(dir, name string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	slug := sanitize(name)
	version := time.Now().UTC().Format("20060102150405")
	for _, suffix := range []string{"up", "down"} {
		path := filepath.Join(dir, fmt.Sprintf("%s_%s.%s.sql", version, slug, suffix))
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("create %s: %w", path, err)
		}
		_ = f.Close()
		slog.Info("created", "file", path)
	}
	return nil
}

func sanitize(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ', r == '-', r == '_':
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "migration"
	}
	return b.String()
}

func usage(fs *flag.FlagSet) func() {
	return func() {
		fmt.Fprintln(os.Stderr, "usage: migrate [flags] <command> [args] [flags]")
		fmt.Fprintln(os.Stderr, "commands: up, down [N], goto V, version, force V, drop, create NAME")
		fmt.Fprintln(os.Stderr, "flags work in any position, e.g.:")
		fmt.Fprintln(os.Stderr, "  migrate -path /opt/NexusHub/migrations force 8")
		fmt.Fprintln(os.Stderr, "  migrate force 8 -path /opt/NexusHub/migrations")
		fs.PrintDefaults()
	}
}
