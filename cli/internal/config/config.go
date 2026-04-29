// Package config loads and persists the CLI's config file.
//
// The file lives at $XDG_CONFIG_HOME/nexushub/config.yaml (or
// ~/.config/nexushub/config.yaml when XDG isn't set). It holds the
// target API URL plus either a token pair (after interactive login)
// or an API key (for unattended automation). Both auth shapes are
// supported; an API key takes precedence when both are populated,
// matching how cron jobs and CI flows typically authenticate.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// File is the on-disk shape. Keep fields lowercase-YAML-tagged so
// operators can hand-edit the file if they prefer.
type File struct {
	APIURL       string    `yaml:"api_url"`
	APIKey       string    `yaml:"api_key,omitempty"`
	AccessToken  string    `yaml:"access_token,omitempty"`
	RefreshToken string    `yaml:"refresh_token,omitempty"`
	AccessExpiry time.Time `yaml:"access_expiry,omitempty"`
	Email        string    `yaml:"email,omitempty"`
}

// DefaultAPIURL is what a fresh install points at. Operators override
// via `nexushub --server=... login` or by editing the config file.
const DefaultAPIURL = "http://localhost:8080"

// Path resolves the config file location. When override is non-empty
// we respect it (test + --config flag path); otherwise we use the
// XDG layout.
func Path(override string) (string, error) {
	if override != "" {
		return filepath.Clean(override), nil
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "nexushub", "config.yaml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home dir: %w", err)
	}
	return filepath.Join(home, ".config", "nexushub", "config.yaml"), nil
}

// Load reads the config file. A missing file returns a zero-value
// File rather than an error so first-run callers can proceed to
// login without a special case.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &File{APIURL: DefaultAPIURL}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if f.APIURL == "" {
		f.APIURL = DefaultAPIURL
	}
	return &f, nil
}

// Save writes the file atomically. Parent directory is created with
// 0o700 so an errant umask doesn't expose the token to the group.
// The file itself is 0o600 — same reasoning, stricter.
func Save(path string, f *File) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir config: %w", err)
	}
	out, err := yaml.Marshal(f)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "config.yaml.*")
	if err != nil {
		return fmt.Errorf("tempfile: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod tempfile: %w", err)
	}
	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write tempfile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close tempfile: %w", err)
	}
	return os.Rename(tmp.Name(), path)
}
