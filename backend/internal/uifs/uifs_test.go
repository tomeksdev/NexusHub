package uifs

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The embedded dist/ in this test build is empty (just a .gitkeep
// marker), so every code path that touches the bundle should land
// in the degraded handler. Release builds get the real frontend
// copied in by goreleaser before `go build` runs.

func TestIsEmptyWithoutBundle(t *testing.T) {
	if !IsEmpty() {
		t.Error("IsEmpty should be true when no index.html is embedded")
	}
}

func TestHandlerDegradedResponse(t *testing.T) {
	h := Handler()
	for _, target := range []string{"/", "/peers", "/assets/index.js"} {
		t.Run(target, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, target, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("status: got %d want %d",
					rec.Code, http.StatusServiceUnavailable)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
				t.Errorf("content-type: got %q want text/plain*", ct)
			}
			if !strings.Contains(rec.Body.String(), "frontend bundle not included") {
				t.Errorf("body missing degraded marker: %q", rec.Body.String())
			}
		})
	}
}

func TestSetCacheHeaders(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"index.html", "no-store"},
		{"favicon.ico", "no-store"},
		{"assets/index-abc.js", "public, max-age=31536000, immutable"},
		{"assets/sub/foo.css", "public, max-age=31536000, immutable"},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			setCacheHeaders(rec, c.path)
			if got := rec.Header().Get("Cache-Control"); got != c.want {
				t.Errorf("Cache-Control: got %q want %q", got, c.want)
			}
		})
	}
}
