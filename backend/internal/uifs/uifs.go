// Package uifs embeds the built React SPA into the API binary and
// serves it with single-page-app routing semantics.
//
// At build time, the frontend bundle from `frontend/dist/` is copied
// into `dist/` here by the release pipeline (see .goreleaser.yaml's
// `before:` hooks) or by `make frontend-build && cp -r
// frontend/dist/* backend/internal/uifs/dist/` during development.
// The embed directive below pulls those bytes into the compiled
// binary so a single `nexushub-api` ships the whole control plane —
// no separate static-file server required for a bare-metal install.
//
// SPA semantics: a request for `/peers/abc` should NOT 404 just
// because no `peers/abc/index.html` exists on disk. React Router
// (or whatever the SPA uses for client-side routing) takes over
// once index.html loads. Handler() therefore falls back to
// index.html for any path that isn't a real embedded file, while
// still 404'ing real misses inside the assets directory (so
// missing /assets/index-XYZ.js shows up as an honest 404 instead
// of HTML).
//
// Empty-build case: if the embedded `dist/` is empty (developer
// ran `go build` without building the frontend first), Handler()
// returns a degraded handler that emits a plain-text "frontend
// bundle missing" message at the appropriate HTTP status. The
// API keeps working; only `/` (and SPA routes) is affected.
package uifs

import (
	"embed"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// dist holds the compiled SPA bundle. The `all:` prefix is
// required so dot-files (e.g. asset hashes that start with `.`) are
// included; without it embed silently skips them.
//
//go:embed all:dist
var dist embed.FS

// Handler returns an http.Handler that serves the embedded SPA.
//
// Routing:
//   - exact-file hit  → serve with the right Content-Type + cache
//     headers
//   - directory hit   → serve dir/index.html
//   - miss            → serve top-level index.html (SPA fallback)
//   - empty bundle    → degraded 503 with a clear operator message
//
// Cache-Control: aggressive `public, max-age=31536000, immutable`
// for anything under /assets/ (content-hashed by Vite), no-store
// for index.html so an updated SPA bundle reaches the operator
// without a hard refresh.
func Handler() http.Handler {
	root, err := fs.Sub(dist, "dist")
	if err != nil {
		// fs.Sub only fails when the prefix isn't found, which
		// means the embed directive captured nothing. That's the
		// "developer forgot to build the frontend" case.
		return degraded()
	}

	// Check whether index.html exists. If it doesn't, the embed
	// captured the directory marker but no real bundle — degrade
	// the same way as the no-Sub case.
	if _, err := fs.Stat(root, "index.html"); err != nil {
		return degraded()
	}

	fileServer := http.FileServer(http.FS(root))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Normalise the request path: trim leading slash, default
		// to index.html when the path is empty.
		reqPath := strings.TrimPrefix(r.URL.Path, "/")
		if reqPath == "" {
			reqPath = "index.html"
		}

		// Try the real file first. If it exists, set cache
		// headers and serve via http.FileServer (which handles
		// Content-Type + If-Modified-Since correctly).
		if f, err := root.Open(reqPath); err == nil {
			info, statErr := f.Stat()
			_ = f.Close()
			if statErr == nil && !info.IsDir() {
				setCacheHeaders(w, reqPath)
				fileServer.ServeHTTP(w, r)
				return
			}
		}

		// Real misses: anything under /assets/ stays a 404 (a
		// missing hashed asset is a bug, not an SPA route). Other
		// paths fall back to index.html for client-side routing.
		if strings.HasPrefix(reqPath, "assets/") ||
			strings.HasPrefix(reqPath, "static/") {
			http.NotFound(w, r)
			return
		}
		serveIndex(w, r, root)
	})
}

// serveIndex writes the embedded index.html as the response body.
// We do it by hand (rather than reusing http.FileServer with the
// path rewritten) so the Content-Type and cache headers are
// explicit and the URL the client sees doesn't change.
func serveIndex(w http.ResponseWriter, r *http.Request, root fs.FS) {
	f, err := root.Open("index.html")
	if err != nil {
		http.Error(w, "index.html missing from embedded bundle",
			http.StatusServiceUnavailable)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
}

// setCacheHeaders picks Cache-Control based on the requested path.
// Hash-fingerprinted assets (Vite's default for everything under
// /assets/) get immutable + a year of caching; the entry HTML and
// everything else stays no-store so an SPA refresh always reaches
// the latest bundle.
func setCacheHeaders(w http.ResponseWriter, reqPath string) {
	dir := path.Dir(reqPath)
	if dir == "assets" || strings.HasPrefix(dir, "assets/") {
		w.Header().Set("Cache-Control",
			"public, max-age=31536000, immutable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
}

// degraded returns the handler used when the embedded SPA bundle
// is missing or empty. Emits a plain-text 503 that names the
// build step the operator skipped — much better than a generic
// 404 that looks like a routing bug.
func degraded() http.Handler {
	const msg = `NexusHub frontend bundle not included in this binary.

Run ` + "`make frontend-build`" + ` and ` + "`cp -r frontend/dist/* backend/internal/uifs/dist/`" + `
before building the API, or use a release tarball — release builds
embed the SPA automatically via the goreleaser ` + "`before:`" + ` hooks.

The REST API is unaffected; try /api/v1/health.
`
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, msg)
	})
}

// IsEmpty reports whether the embedded bundle is missing or
// empty. Useful for the health/diagnostics surface so the operator
// can tell "API up but UI missing" apart from "service down".
func IsEmpty() bool {
	root, err := fs.Sub(dist, "dist")
	if err != nil {
		return true
	}
	_, err = fs.Stat(root, "index.html")
	return errors.Is(err, fs.ErrNotExist)
}
