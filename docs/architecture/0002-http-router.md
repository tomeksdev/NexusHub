# ADR 0002 — HTTP router

- **Status:** Accepted
- **Date:** 2026-04-17
- **Deciders:** @tomeksdev

## Context

Phase 3 starts wiring real HTTP endpoints (auth, peers, rules). CLAUDE.md
lists the choice as "Gin or Echo — decide & document". We need:

- Route groups with per-group middleware (auth vs. public, role gating).
- JSON request binding + validation that plays well with `go-playground/validator`.
- Structured access logs that can be routed through `slog`.
- Low allocation overhead on the hot path (peer list, connection-log ingest).
- A mature middleware ecosystem (rate limiter, request-id, recover, CORS).

## Decision

**Gin** (`github.com/gin-gonic/gin`) as the HTTP router for `cmd/api`.

### Why Gin over Echo

| Concern | Gin | Echo |
|---|---|---|
| Adoption | ~80k★, dominant in Go HTTP stacks | ~30k★, smaller ecosystem |
| Middleware ecosystem | Larger — most third-party middleware ships for Gin first | Smaller, often Gin-compatible only via wrappers |
| Validator integration | `c.ShouldBindJSON` routes directly to `validator/v10` | Similar, but binding ergonomics are slightly less polished |
| Route groups / per-group middleware | First-class | First-class |
| JSON perf | Uses `json-iterator` when built with the `jsoniter` tag | Comparable |
| Familiarity | @tomeksdev has shipped Gin before | — |

Both are acceptable. Gin wins on ecosystem momentum and familiarity; Echo's
type-safe context offers no advantage that justifies the smaller middleware
pool.

### What we are *not* choosing

- `net/http` + `chi` — more idiomatic, but we would hand-roll JSON binding,
  validation, and error envelopes. Not worth the time this phase.
- `fiber` — fasthttp under the hood, incompatible with `net/http.Handler`,
  locks us out of half the middleware ecosystem.
- gRPC — overkill for an admin dashboard; frontend is REST + TanStack Query.

## Consequences

- All HTTP handlers live under `backend/internal/handler/` and accept
  `*gin.Context`.
- Middleware lives under `backend/internal/middleware/` (`RequireAuth`,
  `RequireRole`, request-id, structured logging, recover, rate limit).
- Error envelope format stays as `{"error": "...", "code": "..."}` per
  CLAUDE.md; helpers in `handler/errors.go` centralize this.
- `gin.Default()` is **not** used — it pulls in Gin's own logger. We build
  the engine manually and install a `slog`-backed access logger.
- Tests hit handlers through `httptest.NewRecorder` + `engine.ServeHTTP` so
  no network is involved.

## Rejected alternatives

- **Echo** — viable, but no concrete advantage to justify it.
- **Chi** — too low-level for the current pace; revisit if Gin overhead shows
  up in profiling.
- **Fiber** — fasthttp incompatibility is a dealbreaker.
