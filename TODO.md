# NexusHub v2.0.0 — Development Plan

A 12-phase roadmap from scaffolding to GA. Check boxes as work lands on `dev`.
Phases are sequential in priority but work can overlap where dependencies allow.

> **Legend:** `[x]` done · `[ ]` pending · `(YYYY-MM-DD)` completion date

---

## Phase 1 — Project scaffolding & repo hygiene

- [x] Initialize monorepo directory structure (2026-04-17)
- [x] Initialize Go modules: `backend`, `cli`, `ebpf` (2026-04-17)
- [x] Scaffold React + Vite + TypeScript frontend (2026-04-17)
- [x] Install core frontend deps (Refine, React Query, React Table, React Hook Form, Zod, Lucide, Recharts) (2026-04-17)
- [x] Install dev frontend deps (Tailwind v4 Vite plugin, ESLint, Prettier, Vitest, Testing Library, Playwright, MSW) (2026-04-17)
- [x] Configure Tailwind via `@tailwindcss/vite` plugin (2026-04-17)
- [x] Write `.gitignore`, `.editorconfig`, `commitlint.config.js` (2026-04-17)
- [x] Write `.golangci.yml` (2026-04-17)
- [x] Write `.env.example` (2026-04-17)
- [x] Write `CONTRIBUTING.md`, `SECURITY.md`, `.github/CODEOWNERS`, `.github/dependabot.yml` (2026-04-17)
- [x] Write Docker files: `Dockerfile`, `Dockerfile.dev`, `docker-compose.yml`, `docker-compose.dev.yml` (2026-04-17)
- [x] Write GitHub Actions workflows: `ci`, `security`, `release`, `docker-publish`, `e2e-tests` (2026-04-17)
- [x] Write Go placeholder entry points (`backend/cmd/api`, `backend/cmd/migrate`, `cli/`) (2026-04-17)
- [x] Write `TODO.md` and update `README.md` for v2.0.0 (2026-04-17)
- [x] Set up `main` + `dev` branches and push (2026-04-17)
- [ ] Configure branch protection rules on GitHub (manual)
- [ ] Remove legacy v1.0.0 files (`wg-server-install.sh`, `example.html`) once rewrite is self-sufficient
- [ ] Add `.air.toml` for backend live-reload
- [ ] Add issue templates (bug, feature, security disclosure redirect) under `.github/ISSUE_TEMPLATE/`
- [ ] Add PR template under `.github/pull_request_template.md`
- [ ] Add a `Makefile` with common dev tasks

---

## Phase 2 — Database & migrations

- [x] Choose ORM/query layer (sqlc vs. pgx+scan vs. ent) and document decision (2026-04-17) <!-- completed 2026-04-17: ADR 0001 — sqlc + pgx v5 + golang-migrate -->
- [x] Wire `github.com/golang-migrate/migrate/v4` into `backend/cmd/migrate` (2026-04-17) <!-- completed 2026-04-17: up/down/goto/version/force/drop/create subcommands -->
- [x] Schema: `users`, `sessions`, `refresh_tokens` (2026-04-17) <!-- completed 2026-04-17: migration 001 -->
- [x] Schema: `wg_interfaces`, `wg_peers`, `wg_peer_preshared_keys` (2026-04-17) <!-- completed 2026-04-17: migration 002 -->
- [x] Schema: `ebpf_rules`, `ebpf_rule_bindings` (per-peer attachment) (2026-04-17) <!-- completed 2026-04-17: migration 003 -->
- [x] Schema: `audit_log` (2026-04-17) <!-- completed 2026-04-17: migration 004 -->
- [x] Schema: `api_keys` (optional, for CLI/automation) (2026-04-17) <!-- completed 2026-04-17: migration 005 -->
- [x] Schema: `connection_logs` partitioned by month (2026-04-17) <!-- completed 2026-04-17: migration 006 -->
- [x] Seed script: initial admin user, default interface (2026-04-17) <!-- completed 2026-04-17: backend/cmd/seed -->
- [x] Connection pooling via `pgxpool` (2026-04-17) <!-- completed 2026-04-17: internal/db/pool.go, MaxConns=25 -->
- [x] Unit tests using a real Postgres (no mocks) via testcontainers or compose (2026-04-17) <!-- completed 2026-04-17: backend/internal/dbtest harness + migrations round-trip, schema constraints, seed tests under -tags=integration -->)

---

## Phase 3 — Auth, sessions, RBAC

- [x] Argon2id password hashing helper (2026-04-17) <!-- completed 2026-04-17: internal/auth/password.go -->
- [x] JWT access token + rotating refresh token flow (2026-04-17) <!-- completed 2026-04-17: internal/auth/jwt.go + RotateRefreshToken with reuse detection -->
- [x] Login, logout, refresh, password change endpoints (2026-04-17) <!-- completed 2026-04-17: POST /api/v1/auth/{login,refresh,logout,password} -->
- [x] Roles: `super_admin`, `admin`, `user` (2026-04-17) <!-- completed 2026-04-17: aligned with user_role enum from migration 001; ADR to follow if we re-introduce operator/viewer -->
- [x] Middleware: `RequireAuth`, `RequireRole` (2026-04-17) <!-- completed 2026-04-17: internal/middleware/auth.go -->
- [x] Rate limiting on auth endpoints (2026-04-17) <!-- completed 2026-04-17: internal/middleware/ratelimit.go token-bucket + OnDeny audit hook; wired to /auth/login and /auth/refresh -->)
- [x] Audit-log entries for auth events (2026-04-17) <!-- completed 2026-04-17: internal/repository/audit.go; login/refresh/logout/password_change rows -->
- [ ] Optional: TOTP second factor
- [ ] Optional: SSO/OIDC hook point (not implemented, just planned)
- [x] ADR 0002 — HTTP router (Gin) (2026-04-17) <!-- completed 2026-04-17: docs/architecture/0002-http-router.md -->

> Note: TODO originally listed roles `admin/operator/viewer`; schema uses `super_admin/admin/user`. Phase 3 aligns with schema. Re-evaluate if a three-tier non-admin split is ever needed.

---

## Phase 4 — WireGuard core

- [ ] Abstraction layer over `wgctrl-go` for interface and peer CRUD
- [ ] Key pair generation (server + per-peer), pre-shared key rotation
- [ ] Peer config export (plain text + QR code PNG)
- [ ] Allowed-IPs validation & IP pool management
- [ ] DNS push options per peer
- [ ] Endpoint handling behind NAT
- [ ] Kernel vs. `boringtun` userspace mode detection
- [ ] Startup: reconcile DB state with live kernel state

---

## Phase 5 — eBPF security rules

- [ ] Pick loader: `cilium/ebpf` (Go) vs. libbpf + CO-RE
- [ ] Rule model: per-peer allow/deny lists, L3/L4 filters, rate limits
- [ ] Example programs: peer ingress filter, bandwidth meter, connection counter
- [ ] Userspace map management (add/remove/update rule entries live)
- [ ] Metrics export (maps → Prometheus)
- [ ] Safety: verifier-friendly patterns, bounds checks, no unbounded loops
- [ ] Loader tests in a kernel-ready CI runner
- [ ] Fallback path if kernel lacks BTF or required features

---

## Phase 6 — Backend HTTP API (v1)

- [ ] Router: `chi` or `gin` (decide & document)
- [ ] Structured logging via `slog`
- [ ] Request ID + correlation ID middleware
- [ ] Standardized error envelope + problem+json
- [ ] OpenAPI 3.1 spec under `docs/api/`
- [ ] Endpoints: peers, interfaces, rules, users, audit log, health, metrics
- [ ] Pagination, filtering, sorting conventions
- [ ] Server-Sent Events or WebSocket for live peer/rule state
- [ ] Graceful shutdown

---

## Phase 7 — Frontend application

- [ ] App shell with Refine + routing
- [ ] Auth flow wired to backend (login, refresh, logout)
- [ ] Peers list, peer detail, peer create/edit (with QR download)
- [ ] Interfaces list & detail
- [ ] eBPF rules editor
- [ ] Users & roles admin screen
- [ ] Audit log viewer with filtering
- [ ] Metrics dashboard (Recharts)
- [ ] Dark mode
- [ ] i18n scaffolding
- [ ] Accessible by default (keyboard nav, ARIA, contrast)

---

## Phase 8 — CLI (`nexushub`)

- [ ] Commands: `login`, `peer`, `interface`, `rule`, `user`, `export`, `import`, `doctor`
- [ ] Config file at `~/.config/nexushub/config.yaml`
- [ ] API key auth for unattended use
- [ ] Shell completion generation (bash, zsh, fish)
- [ ] Packaging: `goreleaser` config for binaries + `.deb`/`.rpm`

---

## Phase 9 — Testing

- [ ] Backend unit tests (services, handlers with real DB)
- [ ] Backend integration tests (full HTTP + DB)
- [ ] Frontend unit tests (Vitest + Testing Library)
- [ ] Frontend MSW-backed component tests
- [ ] E2E tests (Playwright) covering: login, peer create, rule attach, audit view
- [ ] eBPF tests in a kernel runner
- [ ] Load test baseline (k6 or vegeta) — document expected RPS and latency targets
- [ ] Coverage gate in CI (threshold TBD)

---

## Phase 10 — Observability

- [ ] Prometheus metrics: HTTP, DB pool, WireGuard peer stats, eBPF counters
- [ ] `/metrics` endpoint + sample Grafana dashboards in `docs/deployment/`
- [ ] OpenTelemetry traces for HTTP + DB
- [ ] Structured audit log with retention policy
- [ ] Alert examples: auth spikes, peer handshake failures, eBPF load errors

---

## Phase 11 — Packaging & deployment

- [ ] Multi-arch (`amd64`, `arm64`) image published to `ghcr.io/tomeksdev/wireguard-install-with-gui`
- [ ] Systemd unit files for bare-metal installs
- [ ] `install.sh` replacement for v1.0.0 (still supports one-liner bootstrap)
- [ ] Example `docker-compose.yml` for operators with TLS via Caddy
- [ ] Kubernetes manifests + Helm chart (`deploy/helm/`)
- [ ] Documented backup/restore procedure

---

## Phase 12 — Docs, release, launch

- [ ] User guide: install, first peer, eBPF rules, backup (`docs/user-guide/`)
- [ ] API reference generated from OpenAPI (`docs/api/`)
- [ ] Deployment guide: Docker, bare-metal, k8s (`docs/deployment/`)
- [ ] Screenshots for README (`docs/assets/screenshots/`)
- [ ] Migration guide from v1.0.0 Python WebGUI
- [ ] Changelog via release-please
- [ ] `v2.0.0` tag → docker-publish workflow pushes images
- [ ] Announce: README badges updated, GitHub release notes, blog/socials
