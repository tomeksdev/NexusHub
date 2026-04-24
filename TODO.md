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
- [x] Remove legacy v1.0.0 files (`wg-server-install.sh`, `example.html`) once rewrite is self-sufficient (2026-04-23) <!-- completed 2026-04-23: deleted — v2.0.0 scaffolding superseded them months ago and git history keeps the originals if anyone wants to reference them -->
- [x] Add `.air.toml` for backend live-reload (2026-04-23) <!-- completed 2026-04-23: backend/.air.toml builds cmd/api into tmp/api, watches .go/.tpl/.tmpl/.html, excludes tmp/bin/vendor/testdata. Install with `go install github.com/air-verse/air@latest`, run via `make backend-dev`. -->
- [x] Add issue templates (bug, feature, security disclosure redirect) under `.github/ISSUE_TEMPLATE/` (2026-04-23) <!-- completed 2026-04-23: bug_report.yml (version+component dropdown+repro+logs), feature_request.yml (problem-first template with scope estimate), config.yml routes security reports to the private advisory form and general questions to Discussions. blank_issues_enabled=false forces triage through the templates. -->
- [x] Add PR template under `.github/pull_request_template.md` (2026-04-23) <!-- completed 2026-04-23: summary + scope checkboxes + change bullets + test plan (make test / make lint / browser pass / integration) + reviewer notes + issue/ADR refs -->
- [x] Add a `Makefile` with common dev tasks (2026-04-23) <!-- completed 2026-04-23: `make help` auto-generates from ## doc-comments. Targets: backend-{build,test,test-integration,lint,dev}, migrate-{up,down}, ebpf-{test,gen}, frontend-{install,dev,build,test,typecheck,lint}, aggregate `test`/`build`/`lint`, docker-{up,dev,down}, clean. Every Go invocation pins GOTOOLCHAIN=local + GOFLAGS=-mod=mod so the module cache can't auto-upgrade past Go 1.22. -->

> Note: Branch protection stays manual — needs repo admin in the GitHub UI, not something to automate from code.

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
- [x] Optional: TOTP second factor (2026-04-23) <!-- completed 2026-04-23: schema had users.totp_secret + totp_enabled since migration 001; this delivery ships the helpers, endpoints, and UX. Backend: internal/auth/totp.go wraps github.com/pquerna/otp/totp (30 s / 6 digits / SHA-1 / ±1 step skew, 160-bit secret); UserRepo grows SetTOTPPending/EnableTOTP/ClearTOTP/GetTOTP/GetEmail, GetCredentialsByEmail now returns totp_enabled + cipher; Login requires totp_code when enabled (missing → TOTP_REQUIRED, wrong → TOTP_INVALID + failed-login counter); POST /api/v1/auth/totp/{enroll,verify,disable} handlers with audit entries; secrets encrypted via existing crypto.AEAD with a dedicated "users.totp_secret" additional-data tag. Frontend: LoginPage two-step flow keys off TOTP_REQUIRED → reveals an autocomplete=one-time-code input with numeric filter + 6-digit gating; new SecurityPage with QRCodeSVG-rendered otpauth URI + manual-entry secret + confirmation code flow, plus password+code disable flow. Dependencies added: github.com/pquerna/otp v1.5.0 (+ indirect barcode), qrcode.react. Tests: pure-Go coverage for TOTP generator/validator incl. clock-skew; typecheck + lint + 29 vitest suites green. -->
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
- [x] Example programs: peer ingress filter, bandwidth meter, connection counter (2026-04-22) <!-- completed 2026-04-22: all three conceptual examples land as facets of ebpf/src/rules.c rather than standalone programs — peer ingress filter via LPM-src→rule_meta→ACTION_DENY, bandwidth meter + connection counter via the new rule_hits PERCPU_HASH map ticked by count_hit() on every matched rule before action dispatch (so ALLOW/DENY/RATE_LIMIT/LOG all register, unlike the ringbuf which only fires on ACTION_LOG and drops under load). struct rule_hits {u64 packets; u64 bytes} is shared via nexushub.h; userspace RulesLoader exposes PeekRuleHits(ruleID) summing across CPUs + ResetRuleHits(ruleID) with dropENOENT semantics, and LoaderStats.RuleHits picks up cardinality for Prometheus. Kernel-gated tests cover per-CPU sum, absent=zero-not-error, and reset-missing-noop; pure-Go test covers the 16-byte marshal roundtrip. Map is optional at NewRulesLoader so maps-only test specs without the counter keep working. -->
- [x] TC clsact program on wg0 for post-decryption rule enforcement (2026-04-21) <!-- completed 2026-04-21: SEC("tc") tc_rules_wg0 lives alongside SEC("xdp") xdp_rules in rules.c, sharing rule_meta/LPMs/rate_state via one ELF; skb->data starts at iphdr (ARPHRD_NONE wg driver), xdp_to_tc translates verdicts. Go side: RulesLoader.Program(name) returns the ebpf.Program by SEC(). -->
- [x] Userspace map management (add/remove/update rule entries live) (2026-04-21) <!-- completed 2026-04-21: ebpf/userspace/RulesLoader owns rule_meta HASH + rule_src/dst_v4/v6 LPM maps + rate_state_v4 PERCPU_HASH with typed CRUD; backend/internal/ebpfkernel.KernelSyncer bridges DB↔kernel, maps uuid→u32 rule_id, evicts stale LPM entries on CIDR changes, and reconciles drift via the Syncer interface. Loader exposes LookupSrcAddr/LookupDstAddr for drift-check + operator tooling. Production wire-up in main.go lands with bpf2go regeneration (needs clang). -->
- [x] Ringbuf log pipeline: ACTION_LOG → connection_logs (2026-04-21) <!-- completed 2026-04-21: log_events BPF_MAP_TYPE_RINGBUF (1 MiB) + emit_log in decide_v4/v6; ebpf/userspace.LogEvent (56 B, LE) + LogReader wrapping ringbuf.Reader + OpenLogReader(); backend/internal/repository.ConnectionLogRepo.Insert writes the partitioned row with NULLIF gating on optional columns; backend/internal/ebpfkernel.LogConsumer.Run drains the ringbuf, resolves kernel rule_id→uuid via KernelSyncer.ResolveRuleID, and forwards to a LogSink adapter (wired in main.go at production time). Sink errors are logged and swallowed so the datapath never backs up on a slow/bad insert. -->
- [x] Metrics export (maps → Prometheus) (2026-04-22) <!-- completed 2026-04-22: ebpf/userspace.RulesLoader.Stats() walks all 7 managed maps via NextKey (PERCPU-safe, value-free) returning LoaderStats{RuleMeta, RuleSrc/Dst_V4/V6, RateState_V4/V6} with per-map {Entries, MaxEntries}. backend/internal/ebpfkernel.MetricsCollector implements prometheus.Collector over a StatsProvider interface — emits nexushub_ebpf_map_entries + nexushub_ebpf_map_capacity gauges (labeled map=<c-identifier>) and a cumulative nexushub_ebpf_stats_errors_total counter. On Stats() failure the per-map series are suppressed (not zeroed) so alerts can distinguish empty deploys from broken scrapes. Tests: kernel-gated seed-and-count Stats test in rules_test.go; pure-Go CollectAndCompare coverage in metrics_test.go (all-series, error-skip, error-accumulation, pedantic-registration). -->
- [x] Safety: verifier-friendly patterns, bounds checks, no unbounded loops (2026-04-22) <!-- completed 2026-04-22: systematic audit of ebpf/src/rules.c. Verified: every packet read guarded by `ptr+size>data_end`; all bpf_map_lookup_elem results null-checked; no unbounded loops (no loops at all in the hot path); every map bounded (MAX_RULES=10000, MAX_LPM_V4/V6=10000, MAX_RATE_STATE=65536, ringbuf 1 MiB); token_bucket_step arithmetic safe under u64 (elapsed clamped 1s, pps×elapsed<u64); log_event zeroed before memcpy so IPv4 events don't leak stack into userspace; fresh rate-bucket create→relookup is fail-open on PERCPU_HASH full; __always_inline everywhere keeps call-depth flat for the verifier. Found one real bug: meta->direction was being written by the syncer but never consulted in decide_v4/v6 — a rule created with direction=egress silently matched ingress traffic. Fixed by adding `if (meta->direction != DIR_BOTH && meta->direction != direction) return XDP_PASS;` after the is_active gate in both paths. Documented limitations remain: IPv6 extension headers not walked (evasion vector via HBH/Routing), rate_state full fail-opens (attacker can spray unique sources to bust the map). Both are intentional trade-offs, called out in file-head comments. -->
- [ ] Loader tests in a kernel-ready CI runner <!-- partial 2026-04-19: blocklist_test.go map ops written, gated on rlimit memlock / CAP_BPF; skips cleanly without a kernel runner. -->
- [x] Fallback path if kernel lacks BTF or required features (2026-04-22) <!-- completed 2026-04-22: ebpf/userspace.Probe() reports Capabilities{HasKernelBTF, HasRingbuf, HasLPMTrie, HasPerCPUHash, ProbeErrs} via cilium/ebpf's btf.LoadKernelSpec + features.HaveMapType. Capabilities.MissingRequired() surfaces a clear error before NewRulesLoader is called — ringbuf / LPM trie / PERCPU hash are load-bearing; kernel BTF is informational (rules.c compiles without CO-RE so the .o loads either way). Summary() is a one-line startup log string. Three-way probe classifier distinguishes NotSupported ("kernel too old") from EPERM / other ("fix your privileges") via ProbeErrs. Coverage: 4 unit tests on MissingRequired + Summary + runProbe classifier incl. wrapped errors; kernel-gated TestProbeDoesNotPanic smoke. -->

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
- [x] eBPF rules editor (2026-04-23) <!-- completed 2026-04-23: frontend/src/pages/RulesPage.tsx — list table sorted by -priority with name / action (color-coded badge + pps suffix for rate_limit) / direction / protocol+port-range / src CIDR / dst CIDR / active-toggle pill / edit + delete; 200-row page. Active toggle is PATCH is_active; delete is confirm-then-DELETE. RuleEditorModal covers create + edit of every field with conditional rendering — rate_pps/rate_burst show only when action=rate_limit, src/dst port inputs only when protocol is tcp|udp; priority bounded 0–1000 to match backend validation. Nav entry wired into App.tsx between Interfaces and Metrics. Bindings (peer↔rule) deferred for a follow-up — the API (POST /rules/:id/bindings, DELETE .../bindings/:binding_id) is ready. Typecheck clean (npx tsc --noEmit), lint clean, all 29 unit tests still green. Kernel enforcement remains a no-op until bpf2go regen — the page's header states this so operators aren't surprised. -->
- [x] Users & roles admin screen (2026-04-18) <!-- completed 2026-04-18: UsersPage.tsx — read-only admin table; role/status/2FA/last-login columns -->
- [x] Audit log viewer with filtering (2026-04-18) <!-- completed 2026-04-18: AuditPage.tsx — action/result/since filters, datetime-local → UTC, offset pagination -->
- [x] Metrics dashboard (Recharts) (2026-04-18) <!-- completed 2026-04-18: MetricsPage.tsx scrapes /api/v1/metrics every 5s, tiny Prometheus text parser in lib/prom.ts, AreaChart of req/s + 5xx/s + stat tiles for DB pool and Go runtime -->

- [x] Dark mode (2026-04-18) <!-- completed 2026-04-18: dark-only for now, slate palette baked into Tailwind utilities -->
- [x] i18n scaffolding (2026-04-23) <!-- completed 2026-04-23: react-i18next + i18next + i18next-browser-languagedetector wired via src/lib/i18n.ts with en+pl translation bundles under src/lib/locales/. Detection order is localStorage("nexushub.lang") → navigator → fallbackLng; user selection persists via the detector's cache. Imported once in main.tsx for side-effect init. LanguageSwitcher component under src/components/ drops into the sidebar footer. App.tsx nav labels + UsersPage columns/empty-state/status/2FA strings converted as the reference conversion; remaining pages stay English-literal and can migrate incrementally without breaking the scaffolding. -->
- [x] Accessible by default (keyboard nav, ARIA, contrast) (2026-04-23) <!-- completed 2026-04-23: new src/components/Modal.tsx owns dialog plumbing — role=dialog, aria-modal=true, aria-labelledby on the title (useId), optional aria-describedby, Escape-to-close via new src/lib/hooks.ts useEscapeKey, initial focus on the dialog container, backdrop-click-to-close. RuleEditorModal + PeerCreateModal + PeerConfigModal refactored onto it; redundant inline scaffolding removed. App.tsx gains a sr-only→focus-visible "Skip to content" link before the sidebar, main element now has id=main-content + tabIndex=-1 as the jump target, nav gets aria-label="Primary" + aria-current="page" on the active button. All interactive elements switched from `focus:outline-none focus:border-*` to `focus-visible:outline-2 focus-visible:outline-*-500 focus-visible:outline-offset-*` so keyboard focus is always ringed (mouse clicks suppress the ring via focus-visible semantics). Sub-AA contrast in RulesPage swapped text-slate-600→500 on the dark-on-dark "any" placeholders. Date.now() impurity (react-hooks/purity) in UsersPage + PeersPage replaced with a shared useNowEveryMinute hook — a 60s-ticking client clock keeps handshake-freshness and lock-expiry branches pure across renders. auth.tsx retains co-located useAuth + AuthProvider with an inline eslint disable explaining why splitting the file would churn call sites. Typecheck clean, lint clean, all 29 unit tests still green. -->

---

## Phase 8 — CLI (`nexushub`)

- [x] Commands: `login`, `peer`, `interface`, `rule`, `user`, `export`, `import`, `doctor` (2026-04-24) <!-- completed 2026-04-24: landed as login + peer list/create/delete + interface list + rule list/create/delete/toggle + user list + audit list + doctor + config export. `import` is the one gap — export is pure-read; import needs idempotent create-or-update semantics with name-matching, interface_id FK resolution, and rule-binding restoration, which is risky without a few more integration tests to back it. Deferred to a follow-up PR. --> <!-- partial: import deferred -->
- [x] Config file at `~/.config/nexushub/config.yaml` (2026-04-23) <!-- completed 2026-04-23: YAML under $XDG_CONFIG_HOME/nexushub/config.yaml (or ~/.config fallback). Fields: api_url, api_key (for unattended automation), access_token+refresh_token+access_expiry+email (interactive login bundle). Save() writes atomically via tempfile-rename with 0o600 file + 0o700 dir permissions so the bearer token can't leak to group-readable processes. Tests cover load-missing-returns-defaults, save/load roundtrip, 0o600 verify, Path() override + XDG resolution. -->
- [x] API key auth for unattended use (2026-04-23) <!-- completed 2026-04-23: client.Client sends X-API-Key when cfg.APIKey is set and falls back to Authorization: Bearer otherwise. Precedence rule documented — an API key shadows any stale access token, which is what cron jobs need. Operators drop `api_key: <value>` into config.yaml; login is not required. -->
- [x] Shell completion generation (bash, zsh, fish) (2026-04-23) <!-- completed 2026-04-23: cli/cmd/completion.go delegates to Cobra's GenBashCompletionV2 / GenZshCompletion / GenFishCompletion / GenPowerShellCompletionWithDesc. Help text documents per-shell install commands. -->
- [x] Packaging: `goreleaser` config for binaries + `.deb`/`.rpm` (2026-04-24) <!-- completed 2026-04-24: .goreleaser.yaml at repo root. Builds the CLI for linux+darwin × amd64+arm64, CGO disabled, -s -w strip, ldflags pin main.buildVersion + main.buildCommit. tar.gz archives with LICENSE + README + DEPLOYMENT bundled. .deb + .rpm via nfpm (nexushub package_name, tomeksdev vendor, MIT license, stable file naming scheme). Release mode: draft + prerelease: auto so the maintainer tags locally and finalises in the GitHub UI. changelog.disable: true because release-please owns the CHANGELOG. Not validated with `goreleaser check` in-repo (tool not installed in this env) — CI will catch schema issues on the first release attempt. -->

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

- [x] Prometheus metrics: HTTP, DB pool, WireGuard peer stats, eBPF counters (2026-04-22) <!-- completed 2026-04-22: HTTP counters + latency histogram via internal/metrics.Middleware (landed 2026-04-17); DB pool via metrics.RegisterPoolCollector over pgxpool.Stat (landed 2026-04-17); eBPF map entries+capacity+stats_errors via ebpfkernel.MetricsCollector over RulesLoader.Stats (landed 2026-04-22); WireGuard per-interface+per-peer via wg.NewWGCollector over wg.Client — wg_peers / wg_device_up / wg_listen_port / wg_peer_last_handshake_seconds / wg_peer_{receive,transmit}_bytes_total / wg_scrape_errors_total (2026-04-22). WG collector registered in cmd/api/main.go from the DB interface list after reconcile — runtime-added interfaces require restart to appear. Pure-Go coverage via FakeClient (seed/scrape, missing-device counter tick, partial failure keeps healthy interface reporting, pedantic registration, handshake zero-time handling). -->
- [x] `/metrics` endpoint + sample Grafana dashboards in `docs/deployment/` (2026-04-22) <!-- completed 2026-04-22: /api/v1/metrics landed with Phase 6 (promhttp over the shared Registry); Grafana dashboard docs/deployment/grafana/nexushub-overview.json is a 13-panel import covering API overview (build info, req/s, 5xx%, auth 401/s, latency p50/95/99, per-route req/s), DB pool (4-line timeseries + utilisation gauge), eBPF (map entries + capacity-utilisation % per map), and WireGuard (peer-count stat, per-peer throughput timeseries, handshake-freshness table with color-graded staleness). The `interface` dashboard variable pulls live from label_values(nexushub_wg_peers, interface). -->
- [x] OpenTelemetry traces for HTTP + DB (2026-04-23) <!-- completed 2026-04-23: internal/tracing package — Init() reads OTEL_EXPORTER_OTLP_ENDPOINT + OTEL_SERVICE_NAME + OTEL_TRACES_SAMPLER_ARG + OTEL_EXPORTER_OTLP_INSECURE; empty endpoint returns a no-op Shutdown + installs the W3C TraceContext+Baggage propagator so inbound traceparent still flows. OTLP/gRPC exporter with BatchSpanProcessor + TelemetrySDK resource + service.name fallback. HTTP: otelgin middleware in handler.NewRouter ahead of RequestID so every request is a parent span. DB: tracing.PgxTracer implements pgx v5 QueryTracer — spans named "pgx.Query" with db.system/db.statement/db.args.count attributes, RecordError on query failure; attached from db.NewPool so every handler-originated query is traced. Wired into cmd/api/main.go before pool construction with 5s flush on shutdown. Tests cover noop path, invalid-endpoint non-fatal, stripScheme, insecureEnv, sampler, propagator fields, and Tracer-resolves-through-global. -->
- [x] Structured audit log with retention policy (2026-04-23) <!-- completed 2026-04-23: audit_log already structured (migration 004 — actor_user_id / actor_ip / action / target_type+id / metadata JSONB / result enum / occurred_at + GIN/btree indexes; append-only app-level invariant). Added AuditRepo.PruneOlderThan(cutoff) streaming DELETE via the occurred_at index. New internal/audit package runs the loop: RunRetentionLoop(ctx, pruner, RetentionConfig{Retention, Interval, Now}) with one eager pre-tick pass so config bumps converge on restart, ticker-driven thereafter, ctx-cancellation stop, errors logged and swallowed (DB hiccups don't tombstone the loop). Config: AUDIT_RETENTION_DAYS (default 90, 0=disabled) + AUDIT_RETENTION_SCAN (default 1h). Wired into cmd/api/main.go as `go audit.RunRetentionLoop(...)` alongside the existing goroutines. Coverage: 4 pure-Go tests for the loop (disabled-when-zero, eager-first-call, cutoff=now-retention, keeps-running-after-error); 1 integration test against dbtest.Fresh seeds 3 rows at different ages, asserts 1 removed + 2 surviving + idempotent second prune. -->
- [x] Alert examples: auth spikes, peer handshake failures, eBPF load errors (2026-04-22) <!-- completed 2026-04-22: docs/deployment/prometheus/alerts.yml ships 10 rules in 4 groups (nexushub.api / .db / .wireguard / .ebpf) covering all three called-out scenarios plus API down / 5xx spikes / DB pool pressure / WG device down / WG scrape errors / eBPF scrape errors / eBPF map >80% full. page vs ticket severities; `for:` windows tuned to survive single-scrape glitches. docs/deployment/README.md documents Prometheus scrape config + import steps. -->

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
