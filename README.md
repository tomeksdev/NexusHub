# NexusHub

> WireGuard VPN management dashboard with eBPF security rules

[![Go](https://img.shields.io/badge/go-1.25-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Node](https://img.shields.io/badge/node-22.x-339933?logo=node.js&logoColor=white)](https://nodejs.org)
[![License](https://img.shields.io/github/license/tomeksdev/NexusHub)](LICENSE)
[![CI](https://github.com/tomeksdev/NexusHub/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/tomeksdev/NexusHub/actions/workflows/ci.yml)

NexusHub is a self-hosted control plane for WireGuard that pairs a modern Go backend and React dashboard with programmable **eBPF** data-plane rules — per-peer allow/deny lists, rate limits, metering, and connection counters enforced in the kernel.

> **Heads up — v2.0.0 is a full rewrite.** The v1.0.0 bash installer + Python WebGUI is being replaced. Legacy files remain in git history for reference.

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
