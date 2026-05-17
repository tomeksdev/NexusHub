# NexusHub

> WireGuard VPN management dashboard with eBPF security rules

[![Status: v2.0.0-preview](https://img.shields.io/badge/status-v2.0.0--preview-yellow)](#-status)
[![No CDN](https://img.shields.io/badge/CDN-free-success)](#-no-cdn-policy)
[![WireGuard](https://img.shields.io/badge/WireGuard-supported-88171A?logo=wireguard&logoColor=white)](https://www.wireguard.com/)
[![eBPF](https://img.shields.io/badge/eBPF-v2.1%20engine-blueviolet)](docs/architecture/0005-rule-engine.md)
[![Go](https://img.shields.io/badge/go-1.25-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Node](https://img.shields.io/badge/node-22.x-339933?logo=node.js&logoColor=white)](https://nodejs.org)
[![PostgreSQL](https://img.shields.io/badge/postgres-16+-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org)
[![License](https://img.shields.io/github/license/tomeksdev/NexusHub)](LICENSE)
[![CI](https://github.com/tomeksdev/NexusHub/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/tomeksdev/NexusHub/actions/workflows/ci.yml)

**Deployment status:**

[![Bare metal](https://img.shields.io/badge/bare--metal-tested-success)](#-status)
[![Docker](https://img.shields.io/badge/docker-testing-yellow)](#-status)
[![Helm](https://img.shields.io/badge/helm-skeleton-lightgrey)](#-status)

---

## What it is

NexusHub is a self-hosted control plane for **WireGuard** that pairs a
Go REST backend and a React dashboard with **programmable eBPF
rules** in the data plane. The kernel enforces per-peer allow/deny
lists, rate limits, metering, and connection counters; the
dashboard manages peers, interfaces, users, and rules.

The architecture has three planes that the operator interacts with
independently:

- **Control plane** — Go API (`backend/`) + Postgres for users,
  peers, interfaces, rules, audit log. JWT + TOTP auth, RBAC over
  `super_admin` / `admin` / `user`.
- **Data plane** — WireGuard kernel module managed via `wgctrl-go`,
  plus eBPF programs (`ebpf/src/rules.c`) attached to **XDP on the
  WAN NIC** (pre-tunnel) and **TC on each `wgN`** (post-decryption).
  Rule updates are map writes — no program reload.
- **Presentation** — React 19 + Vite + Tailwind v4 SPA
  (`frontend/`), CDN-free. Same UI surface as the REST API; CLI
  (`cli/`) gives operators a third route to the same endpoints.

The eBPF data plane uses the v2.1 rule engine: a packed
`BPF_MAP_TYPE_ARRAY` walked per packet via `bpf_loop`, supporting
multiple rules per source CIDR with priority ordering and symmetric
`direction=both` matching. See
[`docs/architecture/0005-rule-engine.md`](docs/architecture/0005-rule-engine.md).

> **v2.0.0 is a full rewrite.** The v1.0.0 bash installer + Python
> WebGUI is being replaced. Legacy files remain in git history;
> migration notes are in
> [`docs/migration-from-v1.md`](docs/migration-from-v1.md).

---

## 📊 Status

NexusHub is in `v2.0.0-preview`. The core control plane is
functional and bare-metal tested; deployment paths (Docker compose
+ Helm) are scaffolded and pending end-to-end verification.

**Working today** (confirmed on bare metal):

- Peer lifecycle — create / edit / rotate PSK / revoke, QR/`.conf`
  export, self-service `/me` for non-admin users
- Multi-location WireGuard interface management with IP-pool
  allocation
- eBPF v2.1 rule engine — multiple rules per source CIDR enforce in
  priority order; per-rule kernel hit counters surfaced in the UI
- Cross-location **system deny rules** auto-generated on interface
  lifecycle, default ON for new pairs, operator overrides preserved
  across regeneration
- Symmetric `direction=both` matching for src+dst-bound rules
- Server-side `allowed_ips` vs client routed networks separated
  cleanly; `0.0.0.0/0` and `::/0` rejected server-side
- Role-based admin/user UI with audit logging on every mutation
- Prometheus collectors + OpenTelemetry traces

**Still TBD before `v2.0.0-preview.1`** (full list in
[`TODO.md`](TODO.md)):

- Docker compose end-to-end smoke pass → flip Docker badge to
  `tested`
- Helm install smoke against kind/k3s → flip Helm badge to
  `tested`
- `scripts/install.sh` verification on a fresh Debian 12 VM
- Screenshots in `docs/assets/screenshots/`
- `docs/DEVELOPMENT.md` + `docs/DEPLOYMENT.md`

**Deferred to a later preview / `v2.0.0`:**

- Dashboard redesign (cards row, bandwidth chart, donut, recent-peers)
- Monitoring rollups + retention (today's monitoring is live-only)
- Mismatch warnings (client routed CIDR not authorised by any rule)

**Tested kernels:** 5.17+ required (`bpf_loop`); 5.8+ for ringbuf.
Older kernels won't load the v2.1 program — the capability probe
fails fast with a clear error.

---

## 🚀 Core features

Inferred from the actual implementation under `backend/internal/handler/`,
`frontend/src/pages/`, and `ebpf/src/rules.c`:

**Peer + interface management**

- Multi-location WireGuard interfaces with per-interface listen port,
  endpoint, MTU, DNS, IP CIDR
- Peer create with auto-IP allocation, custom assigned IP, server-side
  AllowedIPs separate from client routed networks
- PSK rotation per peer
- QR code + `.conf` export rendered live from DB state (no cache)
- Self-service `/me/peers/:id/config` for non-admin owners

**eBPF rule engine (v2.1)**

- `XDP` on WAN NIC + `TC` on each `wgN` clsact ingress hook
- Packed `rule_table_v4` / `rule_table_v6` arrays walked via
  `bpf_loop`; up to 256 active rules per family
- Per-rule actions: `allow`, `deny`, `rate_limit` (per-(rule,src)
  token bucket), `log` (ringbuf event to userspace)
- Auto-generated cross-location **system deny rules** with operator
  overrides preserved across interface changes
- Per-rule hit counters (packets + bytes) surfaced live in the UI

**Auth + RBAC**

- Argon2id passwords, JWT access (15 min) + refresh (7 d) with
  rotation + reuse detection
- TOTP enrollment + recovery codes
- API keys for CLI / automation
- Roles: `super_admin` / `admin` / `user`
- Audit log on every mutation with structured retention policy

**Observability**

- Prometheus `/api/v1/metrics` covering HTTP (req/s, p50/95/99
  latency, status), DB pool, eBPF map cardinality + scrape errors,
  WireGuard per-peer (handshake age, RX/TX, listen port)
- Sample Grafana dashboard at `docs/deployment/grafana/`
- OpenTelemetry traces for HTTP + DB via OTLP/gRPC
- Alert rules at `docs/deployment/prometheus/alerts.yml`

---

## 🛠️ Tech stack matrix

Verified from `backend/go.mod`, `frontend/package.json`,
`docker/Dockerfile`, and Tailwind v4 Vite plugin config.

| Layer | Choice | Version |
|---|---|---|
| Backend language | Go | 1.25 (`go.mod`), 1.26 build image (`docker/Dockerfile`) |
| HTTP router | Gin | latest (`github.com/gin-gonic/gin`) |
| DB driver | pgx native | v5 |
| Migrations | golang-migrate | v4 |
| Logging | `log/slog` | stdlib |
| eBPF loader | cilium/ebpf | latest; clang ≥ 14 at build time only |
| eBPF program | C → BPF via `bpf2go` | linux/bpf.h, kernel ≥ 5.17 (`bpf_loop`) |
| WireGuard control | `wgctrl-go` | upstream |
| Database | PostgreSQL | 16+ (CIDR[], CHECK, native partitioning) |
| Frontend framework | React | 19.2 |
| Bundler | Vite | latest |
| Type system | TypeScript | strict mode |
| Styling | Tailwind CSS | 4.2 via `@tailwindcss/vite` |
| Server state | TanStack Query | 5.x |
| Tables | TanStack Table | 8.x |
| Forms | React Hook Form + Zod | RHF 7.x, Zod 4.x |
| Icons | Lucide | 1.x |
| Charts | Recharts | 3.x |
| QR codes | `qrcode.react` | 4.x |
| Frontend test | Vitest + Testing Library | Vitest 4.x, RTL 16.x |
| E2E | Playwright | 1.x |
| Backend test | Go `testing` + testcontainers-go | testcontainers v0.42 |
| CLI | Cobra | — |
| Container base | Debian Bookworm slim | non-root `USER 10001` |
| CI/CD | GitHub Actions | ci / security / release / docker-publish / e2e |

---

## 📂 Directory structure

```
backend/      Go REST API, migration runner, seeder
cli/          `nexushub` CLI built on Cobra
ebpf/         eBPF C programs + Go userspace loader (bpf2go-generated)
frontend/     React 19 + Vite + Tailwind v4 SPA (CDN-free)
migrations/   PostgreSQL up/down migrations driven by golang-migrate
docker/       Dockerfile (multi-stage, multi-arch) + compose files + Caddyfile
deploy/       systemd unit + env template, Helm chart
docs/         API reference (rendered from OpenAPI), architecture ADRs,
              deployment runbooks, user guide
scripts/      install.sh (bare-metal one-liner), backup.sh, restore.sh
tests/        End-to-end Playwright suites + integration fixtures
.github/      Actions workflows, issue templates, PR template
```

---

## ⚙️ Fast-track startup

### Docker compose (recommended for evaluation)

```bash
git clone https://github.com/tomeksdev/NexusHub.git
cd NexusHub
cp docker/.env.example docker/.env   # set JWT_SECRET, PEER_KEY_ENCRYPTION_KEY, DB creds
docker compose -f docker/docker-compose.yml up -d
```

Dashboard at <http://localhost:8080>. The first-admin password is
printed in the `api` container's logs on first boot — rotate it
immediately via the UI.

### Bare-metal (Debian 12 / Ubuntu 24.04)

```bash
curl -fsSL https://raw.githubusercontent.com/tomeksdev/NexusHub/main/scripts/install.sh \
  | sudo NEXUSHUB_VERSION=v2.0.0-preview.1 bash
```

The installer creates the `nexushub` system user, downloads the
release tarball, drops the systemd unit at
`/etc/systemd/system/nexushub-api.service`, and seeds
`/etc/nexushub/env` with a chmod-600 template. Edit the env file
(`JWT_SECRET`, `PEER_KEY_ENCRYPTION_KEY`, `DB_*`), then:

```bash
sudo systemctl enable --now nexushub-api
```

### Local dev (hot reload)

```bash
# Database
docker compose -f docker/docker-compose.dev.yml up -d postgres

# Backend with live-reload (requires `go install github.com/air-verse/air@latest`)
make backend-dev

# Frontend
cd frontend && npm install && npm run dev
```

See [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) for the full
contributor playbook.

### Helm (Kubernetes)

```bash
helm install nexushub ./deploy/helm/nexushub \
  --set secrets.jwtSecret=$(openssl rand -hex 32) \
  --set secrets.peerKeyEncryptionKey=$(openssl rand -hex 32) \
  --set postgres.existingSecret=nexushub-postgres
```

See [`deploy/helm/nexushub/README.md`](deploy/helm/nexushub/README.md)
for `values.yaml` reference and the data-plane (`dataPlane.enabled`)
toggle.

---

## 🔒 No-CDN policy

NexusHub does **not** depend on external CDN assets. The frontend
bundles its own JS, CSS, fonts, and icons via Vite —
`npm run build` produces a self-contained `dist/` that works in
air-gapped deployments. No `cdn.jsdelivr.net`, no
`fonts.googleapis.com`, no remote font loaders. A fresh load in
DevTools should show only same-origin requests.

If you contribute a UI change, keep this invariant: don't add
`<script src="https://...">` or `<link href="https://...">`
references; install the package and import locally.

---

## Documentation

| Doc | What it covers |
|---|---|
| [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) | Contributor playbook — workspace setup, dev commands, testing, contribution rules |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | Production operations — kernel/network prerequisites, env vars, hardening |
| [`docs/user-guide/`](docs/user-guide/) | Operator-facing usage: first peer, rules, backup |
| [`docs/api/index.html`](docs/api/index.html) | OpenAPI-rendered API reference |
| [`docs/architecture/`](docs/architecture/) | ADRs — DB stack, HTTP router, eBPF loader, rule model, v2.1 rule engine |
| [`docs/deployment/`](docs/deployment/) | Per-shape runbooks (compose / bare-metal / Helm), backup/restore, observability, load testing |
| [`CHANGELOG.md`](CHANGELOG.md) | Per-release notes (Keep-a-Changelog) |
| [`TODO.md`](TODO.md) | Pre-`v2.0.0-preview.1` punch list and acceptance gate |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Branch + commit conventions |
| [`SECURITY.md`](SECURITY.md) | Security disclosure process |

---

## Contributing

Branch off `dev`, follow Conventional Commits, open a PR against
`dev`. `main` is production-only.

Security issues — see [SECURITY.md](SECURITY.md); do not file them
publicly.

---

## License

See [LICENSE](LICENSE).
