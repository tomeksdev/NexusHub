# NexusHub

> WireGuard VPN management dashboard with eBPF security rules

[![Status: v2.0.0-preview](https://img.shields.io/badge/status-v2.0.0--preview-yellow)](#status)
[![No CDN](https://img.shields.io/badge/CDN-free-success)](#no-cdn-policy)
[![WireGuard](https://img.shields.io/badge/WireGuard-supported-88171A?logo=wireguard&logoColor=white)](https://www.wireguard.com/)
[![eBPF](https://img.shields.io/badge/eBPF-v2.1%20engine-blueviolet)](docs/architecture/0005-rule-engine.md)
[![Go](https://img.shields.io/badge/go-1.25-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Node](https://img.shields.io/badge/node-22.x-339933?logo=node.js&logoColor=white)](https://nodejs.org)
[![PostgreSQL](https://img.shields.io/badge/postgres-16+-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org)
[![License](https://img.shields.io/github/license/tomeksdev/NexusHub)](LICENSE)
[![CI](https://github.com/tomeksdev/NexusHub/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/tomeksdev/NexusHub/actions/workflows/ci.yml)

**Deployment status:**

[![Bare metal](https://img.shields.io/badge/bare--metal-tested-success)](#status)
[![Docker](https://img.shields.io/badge/docker-testing-yellow)](#status)
[![Helm](https://img.shields.io/badge/helm-planned-lightgrey)](#status)

NexusHub is a self-hosted control plane for WireGuard that pairs a modern Go backend and React dashboard with programmable **eBPF** data-plane rules — per-peer allow/deny lists, rate limits, metering, and connection counters enforced in the kernel.

> **Heads up — v2.0.0 is a full rewrite.** The v1.0.0 bash installer + Python WebGUI is being replaced. Legacy files remain in git history for reference.

---

## Status

NexusHub is in **`v2.0.0-preview`** — the core control plane is functional and tested on bare metal, but several features are still landing before the production `v2.0.0` cut.

**Working today:**

- Peer lifecycle (create, edit, rotate PSK, revoke, QR/`.conf` export)
- Multi-location WireGuard interface management with IP-pool allocation
- eBPF rule engine v2.1 — per-packet iteration over a packed array via `bpf_loop`, multiple rules per source CIDR enforced in priority order
- Per-rule kernel hit counters surfaced in the dashboard
- Role-based admin/user UI with audit logging on every mutation
- Self-service `/me/peers/:id/config` for non-admin users
- Server-side AllowedIPs vs client routed networks separated cleanly (round 14)

**Still TBD before `v2.0.0`:**

- Default-deny system rules for cross-location traffic (operator-defined rules work; auto-generated baseline doesn't yet)
- Dashboard redesign + monitoring rollups
- Docker compose end-to-end test pass
- Helm chart
- Public installer script (`scripts/install.sh`)

**Tested kernels:** 6.8+ (bpf_loop, ringbuf). Older kernels load the program but lose enforcement.

## No-CDN policy

NexusHub does **not** depend on external CDN assets. The frontend bundles its own JS, CSS, fonts, and icons via Vite — `npm run build` produces a self-contained `dist/` that works in air-gapped deployments. No `cdn.jsdelivr.net`, no `fonts.googleapis.com`, no remote font loaders. The browser network tab on a fresh load should show only same-origin requests.

If you contribute a UI change, keep this invariant: don't add `<script src="https://...">` or `<link href="https://...">` references; install the package and import locally.

---

## Features

- **Peer lifecycle** — create, rotate, revoke peers with QR-code/config export
- **Interface management** — multiple `wg*` interfaces, IP pool allocation, DNS push
- **eBPF security rules** — per-peer filters, bandwidth metering, connection limits enforced in-kernel
- **Role-based access** — admin / operator / viewer, with audit logging of every mutation
- **CLI + API + Dashboard** — same capabilities across `nexushub` CLI, REST API, and web UI
- **Observability** — Prometheus metrics, OpenTelemetry traces, Grafana dashboards
- **Deploy anywhere** — multi-arch Docker image, bare-metal systemd, Kubernetes (Helm)

## Quick start — Docker

```bash
git clone https://github.com/tomeksdev/NexusHub.git && cd NexusHub
cp .env.example .env
docker compose -f docker/docker-compose.yml up -d
```

The dashboard will be available at `http://localhost:8080`. Change `JWT_SECRET` and database credentials in `.env` before exposing to a network.

## Quick start — Linux (bare metal)

> The v2.0.0 installer is in development — see Phase 11 in [TODO.md](TODO.md). In the meantime the Docker route above is recommended.

## Screenshots

_Screenshots will land in `docs/assets/screenshots/` as the UI comes together._

## Tech stack

| Layer           | Choice                                                               |
| --------------- | -------------------------------------------------------------------- |
| Backend         | Go 1.25, `chi`/`gin` router, `slog`, `pgx`                           |
| Database        | PostgreSQL 16                                                        |
| Migrations      | `golang-migrate`                                                     |
| WireGuard       | `wgctrl-go`                                                          |
| eBPF            | `cilium/ebpf` (Go loader) + CO-RE                                    |
| Frontend        | React 19, TypeScript, Vite, Refine, React Query, React Table         |
| UI / styling    | Tailwind CSS v4 (Vite plugin), Lucide icons, Recharts                |
| Testing         | Go `testing` + testcontainers, Vitest + Testing Library, Playwright  |
| CLI             | Cobra                                                                |
| Container       | Debian Bookworm slim, multi-stage build, runs as non-root            |
| CI/CD           | GitHub Actions + Release Please + Trivy + CodeQL + Gitleaks          |

## Project layout

```
backend/     Go API server and migration tool
cli/         `nexushub` CLI (Cobra)
ebpf/        eBPF programs + userspace loader
frontend/    React + Vite + TypeScript dashboard
migrations/  SQL migration files
docker/      Dockerfile, Dockerfile.dev, compose files
docs/        API reference, deployment, user guide, screenshots
tests/       E2E (Playwright), integration, fixtures
scripts/     Helper scripts
```

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md). Short version: branch off `dev`, follow Conventional Commits, open a PR against `dev`. `main` is production-only.

Security issues: see [SECURITY.md](SECURITY.md) — do not file them publicly.

## Roadmap

The full 12-phase plan lives in [TODO.md](TODO.md).

## License

See [LICENSE](LICENSE).
