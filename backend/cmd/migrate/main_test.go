package main

import (
	"reflect"
	"testing"
)

func TestExtractStringFlag(t *testing.T) {
	t.Parallel()
	// All four spellings + flag-after-positional + flag-before-positional
	// + missing flag map to the same canonical (cmd, args) shape so the
	// real bug — "force 8 -path X" — never resurfaces silently.
	cases := []struct {
		name     string
		argv     []string
		want     string
		wantRest []string
	}{
		{
			name:     "absent",
			argv:     []string{"force", "8"},
			want:     "",
			wantRest: []string{"force", "8"},
		},
		{
			name:     "short space",
			argv:     []string{"-path", "/opt/m", "force", "8"},
			want:     "/opt/m",
			wantRest: []string{"force", "8"},
		},
		{
			name:     "long space",
			argv:     []string{"--path", "/opt/m", "force", "8"},
			want:     "/opt/m",
			wantRest: []string{"force", "8"},
		},
		{
			name:     "short equals",
			argv:     []string{"-path=/opt/m", "force", "8"},
			want:     "/opt/m",
			wantRest: []string{"force", "8"},
		},
		{
			name:     "long equals",
			argv:     []string{"--path=/opt/m", "force", "8"},
			want:     "/opt/m",
			wantRest: []string{"force", "8"},
		},
		{
			// The original bug. Cobra and most CLI tools accept this
			// ordering; Go's stdlib flag pkg doesn't. Pre-walking
			// rescues it.
			name:     "flag after positional",
			argv:     []string{"force", "8", "-path", "/opt/m"},
			want:     "/opt/m",
			wantRest: []string{"force", "8"},
		},
		{
			name:     "flag interleaved",
			argv:     []string{"force", "-path=/opt/m", "8"},
			want:     "/opt/m",
			wantRest: []string{"force", "8"},
		},
		{
			name:     "last occurrence wins",
			argv:     []string{"-path", "/old", "force", "8", "-path", "/new"},
			want:     "/new",
			wantRest: []string{"force", "8"},
		},
		{
			// `-path` at the very end with no following arg leaves
			// value empty — caller sees the absent path and falls
			// back to defaultMigrationsPath. Better than crashing.
			name:     "trailing flag without value",
			argv:     []string{"force", "8", "-path"},
			want:     "",
			wantRest: []string{"force", "8"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, rest := extractStringFlag(tc.argv, "-path", "--path")
			if got != tc.want {
				t.Errorf("value: want %q, got %q", tc.want, got)
			}
			if !reflect.DeepEqual(rest, tc.wantRest) {
				t.Errorf("rest: want %v, got %v", tc.wantRest, rest)
			}
		})
	}
}
