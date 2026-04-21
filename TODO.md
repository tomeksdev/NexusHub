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

- [x] Abstraction layer over `wgctrl-go` for interface and peer CRUD (2026-04-18) <!-- completed 2026-04-18: internal/wg/client.go Client iface + KernelClient/FakeClient -->
- [x] Key pair generation (server + per-peer), pre-shared key rotation (2026-04-18) <!-- completed 2026-04-18: internal/wg/keys.go + POST /peers/:id/rotate-psk with wg_peer_preshared_keys history -->
- [x] Peer config export (plain text + QR code PNG) (2026-04-18) <!-- completed 2026-04-18: GET /peers/:id/config and /config.png via skip2/go-qrcode -->
- [x] Allowed-IPs validation & IP pool management (2026-04-18) <!-- completed 2026-04-18: internal/wg/ippool.go AllocateIP with network/broadcast/interface-addr reservation -->
- [x] DNS push options per peer (2026-04-18) <!-- completed 2026-04-18: peer.DNS column + render fallback peer → interface → default -->
- [x] Endpoint handling behind NAT (2026-04-18) <!-- completed 2026-04-18: render fallback peer.Endpoint → iface.Endpoint → WG_ENDPOINT -->
- [x] Kernel vs. `boringtun` userspace mode detection (2026-04-18) <!-- completed 2026-04-18: internal/wg/mode.go + GET /wg/status surfaces wgtypes.DeviceType -->
- [x] Startup: reconcile DB state with live kernel state (2026-04-18) <!-- completed 2026-04-18: internal/wg/reconcile.go + cmd/api/main.go loadDBInterfaces -->

> Note: kernel apply on peer/interface CRUD is best-effort (log + continue) — the reconciler converges on next restart if a live netlink call fails. This matches the invariant that the DB is source of truth.

---

## Phase 5 — eBPF security rules

- [x] Pick loader: `cilium/ebpf` (Go) vs. libbpf + CO-RE (2026-04-19) <!-- completed 2026-04-19: ADR 0003 — cilium/ebpf v0.16 + bpf2go, cgo-free, CO-RE via BTF. -->
- [x] Rule model: per-peer allow/deny lists, L3/L4 filters, rate limits (2026-04-19) <!-- completed 2026-04-19: ADR 0004 — XDP(eth0) + TC(wg0), LPM_TRIE per family, HASH rule_meta, PERCPU_HASH rate_state, map-driven updates. -->
- [ ] Example programs: peer ingress filter, bandwidth meter, connection counter <!-- partial 2026-04-21: ebpf/src/rules.c is the full-gate — XDP on eth0 + TC on wg0 sharing one map set, LPM src → rule_meta → protocol + TCP/UDP port-range match → action switch, with IPv4 token-bucket rate-limiting via rate_state_v4 PERCPU_HASH, and a BPF_MAP_TYPE_RINGBUF log_events sink that emits a 56-byte log_event on every ACTION_LOG hit (ts/rule_id/ports/bytes/action/proto/family/direction + src/dst addrs). IPv6 rate-limiting still pending. -->
- [x] TC clsact program on wg0 for post-decryption rule enforcement (2026-04-21) <!-- completed 2026-04-21: SEC("tc") tc_rules_wg0 lives alongside SEC("xdp") xdp_rules in rules.c, sharing rule_meta/LPMs/rate_state via one ELF; skb->data starts at iphdr (ARPHRD_NONE wg driver), xdp_to_tc translates verdicts. Go side: RulesLoader.Program(name) returns the ebpf.Program by SEC(). -->
- [x] Userspace map management (add/remove/update rule entries live) (2026-04-21) <!-- completed 2026-04-21: ebpf/userspace/RulesLoader owns rule_meta HASH + rule_src/dst_v4/v6 LPM maps + rate_state_v4 PERCPU_HASH with typed CRUD; backend/internal/ebpfkernel.KernelSyncer bridges DB↔kernel, maps uuid→u32 rule_id, evicts stale LPM entries on CIDR changes, and reconciles drift via the Syncer interface. Loader exposes LookupSrcAddr/LookupDstAddr for drift-check + operator tooling. Production wire-up in main.go lands with bpf2go regeneration (needs clang). -->
- [x] Ringbuf log pipeline: ACTION_LOG → connection_logs (2026-04-21) <!-- completed 2026-04-21: log_events BPF_MAP_TYPE_RINGBUF (1 MiB) + emit_log in decide_v4/v6; ebpf/userspace.LogEvent (56 B, LE) + LogReader wrapping ringbuf.Reader + OpenLogReader(); backend/internal/repository.ConnectionLogRepo.Insert writes the partitioned row with NULLIF gating on optional columns; backend/internal/ebpfkernel.LogConsumer.Run drains the ringbuf, resolves kernel rule_id→uuid via KernelSyncer.ResolveRuleID, and forwards to a LogSink adapter (wired in main.go at production time). Sink errors are logged and swallowed so the datapath never backs up on a slow/bad insert. -->
- [ ] Metrics export (maps → Prometheus)
- [ ] Safety: verifier-friendly patterns, bounds checks, no unbounded loops
- [ ] Loader tests in a kernel-ready CI runner <!-- partial 2026-04-19: blocklist_test.go map ops written, gated on rlimit memlock / CAP_BPF; skips cleanly without a kernel runner. -->
- [ ] Fallback path if kernel lacks BTF or required features

---

## Phase 6 — Backend HTTP API (v1)

- [x] Router: `chi` or `gin` (decide & document) (2026-04-17) <!-- completed 2026-04-17: Gin, ADR 0002 -->
- [x] Structured logging via `slog` (2026-04-17) <!-- completed 2026-04-17: slog default + accessLog middleware -->
- [x] Request ID + correlation ID middleware (2026-04-18) <!-- completed 2026-04-18: internal/middleware/requestid.go, echoed in X-Request-ID and log lines -->
- [x] Standardized error envelope + problem+json (2026-04-17) <!-- completed 2026-04-17: internal/apierror + handler.writeError -->
- [x] OpenAPI 3.1 spec under `docs/api/` (2026-04-18) <!-- completed 2026-04-18: spec at backend/internal/openapi/openapi.yaml, embedded via go:embed, served at GET /api/v1/openapi.yaml (public). docs/api/README.md points to it. -->

- [ ] Endpoints: peers, interfaces, rules, users, audit log, health, metrics <!-- peers/interfaces/health/metrics/users/audit-log done 2026-04-18; rules blocked by Phase 5 -->
- [x] Pagination, filtering, sorting conventions (2026-04-18) <!-- completed 2026-04-18: internal/httppage package with {items,total,limit,offset,sort} envelope; applied to /peers, /interfaces, /users, /audit-log -->
- [x] Server-Sent Events or WebSocket for live peer/rule state (2026-04-18) <!-- completed 2026-04-18: GET /api/v1/peers/events — SSE, 5s kernel poll diff, `snapshot` + `peer` + `ping` event types -->
- [x] Graceful shutdown (2026-04-17) <!-- completed 2026-04-17: srv.Shutdown with 15s timeout, SIGINT/SIGTERM via signal.NotifyContext -->

> Phase 6 complete as far as the backend can go without Phase 5 (rules endpoints are blocked on the eBPF rule loader). Users + audit-log list endpoints (GET /users, GET /audit-log) and the SSE peer stream landed 2026-04-18.

---

## Phase 7 — Frontend application

- [x] App shell with sidebar + page switcher (2026-04-18) <!-- completed 2026-04-18: frontend/src/App.tsx — Tailwind dark shell, sidebar nav, main content area. Refine integration deferred until routing needs justify the extra surface. -->
- [x] Auth flow wired to backend (login, refresh, logout) (2026-04-18) <!-- completed 2026-04-18: frontend/src/lib/api.ts + auth.tsx — access token in memory, refresh in localStorage, pre-expiry refresh + 401 retry, LoginPage.tsx -->
- [x] Peers list, peer detail, peer create/edit (with QR download) (2026-04-18) <!-- completed 2026-04-18: list + live SSE + QR/conf modal + PeerCreateModal (POST /peers — server-side key gen, auto IP alloc) + delete + rotate-PSK. Peer *edit* deferred — backend has no PATCH endpoint today. -->
- [x] Interfaces list & detail (2026-04-18) <!-- completed 2026-04-18: InterfacesPage.tsx merges DB list with /wg/status live devices on a 10s refetch -->
- [ ] eBPF rules editor
- [x] Users & roles admin screen (2026-04-18) <!-- completed 2026-04-18: UsersPage.tsx — read-only admin table; role/status/2FA/last-login columns -->
- [x] Audit log viewer with filtering (2026-04-18) <!-- completed 2026-04-18: AuditPage.tsx — action/result/since filters, datetime-local → UTC, offset pagination -->
- [x] Metrics dashboard (Recharts) (2026-04-18) <!-- completed 2026-04-18: MetricsPage.tsx scrapes /api/v1/metrics every 5s, tiny Prometheus text parser in lib/prom.ts, AreaChart of req/s + 5xx/s + stat tiles for DB pool and Go runtime -->

- [x] Dark mode (2026-04-18) <!-- completed 2026-04-18: dark-only for now, slate palette baked into Tailwind utilities -->
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

- [ ] Backend unit tests (services, handlers with real DB) <!-- partial 2026-04-19: users + audit list endpoints have integration coverage; wg_test CIDR failures fixed via migration 007 (address CIDR→INET) + host() on scan — all handler integration tests now green. -->
- [ ] Backend integration tests (full HTTP + DB) <!-- partial 2026-04-19: auth + users + audit + wg flows covered via dbtest.Fresh under the `integration` build tag. -->
- [x] Frontend unit tests (Vitest + Testing Library) (2026-04-19) <!-- completed 2026-04-19: vitest + jsdom config, setupFiles/MSW server in src/test, pure-unit tests for lib/prom.ts and lib/sse.ts. -->
- [x] Frontend MSW-backed component tests (2026-04-19) <!-- completed 2026-04-19: src/lib/api.test.ts exercises login/logout/refresh/401-retry/token-lifecycle against MSW mocks. -->
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

- [ ] Multi-arch (`amd64`, `arm64`) image published to `ghcr.io/tomeksdev/nexushub`
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
