package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadMissingReturnsDefaults(t *testing.T) {
	f, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if f.APIURL != DefaultAPIURL {
		t.Errorf("APIURL = %q, want %q", f.APIURL, DefaultAPIURL)
	}
	if f.AccessToken != "" || f.RefreshToken != "" || f.APIKey != "" {
		t.Errorf("fresh config carries credentials: %+v", f)
	}
}

func TestSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	want := &File{
		APIURL:       "https://nexushub.example.com",
		AccessToken:  "at",
		RefreshToken: "rt",
		AccessExpiry: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		Email:        "alice@example.com",
	}
	if err := Save(path, want); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.APIURL != want.APIURL || got.AccessToken != want.AccessToken ||
		got.RefreshToken != want.RefreshToken || got.Email != want.Email ||
		!got.AccessExpiry.Equal(want.AccessExpiry) {
		t.Errorf("roundtrip mismatch\nwant %+v\n got %+v", want, got)
	}
}

func TestSavePermissionsAre600(t *testing.T) {
	// The file carries a bearer token. World-readable is a silent
	// credential leak so verify the stricter mode is actually set.
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	if err := Save(path, &File{APIURL: "x"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("perm = %o, want 600", mode)
	}
}

func TestPathRespectsOverride(t *testing.T) {
	got, err := Path("/explicit/path/config.yaml")
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if got != "/explicit/path/config.yaml" {
		t.Errorf("override ignored: %q", got)
	}
}

func TestPathRespectsXDG(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/xdg/root")
	got, err := Path("")
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if got != "/xdg/root/nexushub/config.yaml" {
		t.Errorf("XDG not respected: %q", got)
	}
}
