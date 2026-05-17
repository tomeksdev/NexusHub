# NexusHub — `v2.0.0-preview.1` punch list

This file is the gate between `dev` and the first public preview tag.
Every unchecked box is something the operator should confirm before
pushing the tag. The full historical 12-phase plan was archived once
the core control plane shipped — refer to git log and `CHANGELOG.md`
for the per-feature history.

> **Legend:** `[x]` done · `[ ]` pending

## ✅ Already on `dev`

Tested on bare metal across rounds 10–18.

- [x] Peer lifecycle — create / edit / rotate PSK / revoke
- [x] Server-side `allowed_ips` vs client routed networks separation
- [x] `0.0.0.0/0` + `::/0` rejected server-side
- [x] Migration 011 — strip legacy full-tunnel server-side filters
- [x] Migration 012 — `ebpf_rules.owner` (admin | system)
- [x] eBPF v2.1 rule engine — per-packet `bpf_loop` over packed array;
      multiple rules per source CIDR enforce in priority order
- [x] Per-rule kernel hit counters surfaced in the dashboard
- [x] Cross-location system deny rules — auto-generated on interface
      lifecycle, default ON for new pairs, operator overrides
      preserved across regenerations, kernel reconciles atomically
- [x] System-rules sweep endpoints (`enable-all` / `disable-all`)
- [x] `direction=both` symmetric matching for src+dst-bound rules
- [x] Self-service `/me/peers/:id/config` for non-admin users
- [x] Audit log on every mutation + retention loop
- [x] Sidebar cleanup — unfinished Configuration section hidden
- [x] README badges + Status section + No-CDN policy
- [x] CHANGELOG.md with v2.0.0-preview.1 entry
- [x] Multi-arch Docker image build + GHCR publish workflow
- [x] systemd unit + `/etc/nexushub/env.example` (`deploy/systemd/`)
- [x] `scripts/install.sh` for bare-metal Debian/Ubuntu
- [x] `docker/docker-compose.yml` + `docker-compose.prod.yml` + Caddy
- [x] Helm chart skeleton at `deploy/helm/nexushub/`
- [x] `scripts/backup.sh` + `scripts/restore.sh` + `docs/deployment/backup-restore.md`
- [x] Prometheus collectors (HTTP, DB pool, eBPF map cardinality, WG peer stats)
- [x] OpenTelemetry traces for HTTP + DB
- [x] API reference rendered to `docs/api/index.html` from OpenAPI 3.0
- [x] Top-level `docs/deployment/README.md` (compose / bare-metal / Helm shapes)
- [x] User guide at `docs/user-guide/README.md`

## 🟥 Must land before tagging `v2.0.0-preview.1`

- [ ] **`docs/DEVELOPMENT.md`** — local workspace setup, codebase
      mechanics (hot-reload / dev DB), testing & linting commands,
      contribution rules. Round 19 in flight.
- [ ] **`docs/DEPLOYMENT.md`** — single landing doc that points at
      the existing `docs/deployment/` runbooks, names the
      kernel/network prerequisites in one place, and lists every
      env var the operator needs to set. Round 19 in flight.
- [ ] **Docker compose end-to-end smoke** — `docker compose -f
      docker/docker-compose.yml up -d` on a clean host, dashboard
      reaches `/api/v1/health` 200, a smoke peer creates + connects.
      Flip the Docker badge in README from `testing` → `tested`.
- [ ] **Helm chart install smoke** — `helm install nexushub
      ./deploy/helm/nexushub` against a kind / k3s cluster produces
      a Running pod with `/health` 200. Flip the Helm badge from
      `planned` → `tested`.
- [ ] **Bare-metal `install.sh` smoke** — on a fresh Debian 12 VM,
      `curl -fsSL ... | sudo bash` produces a running nexushub-api
      service and the dashboard responds. The script already exists;
      this is the verification, not a build task.
- [ ] **Screenshots** in `docs/assets/screenshots/` for the README —
      dashboard, peers list, rules table, peer config modal with QR.
- [ ] **Tag + push** — promote CHANGELOG's `[Unreleased]` header to
      `[v2.0.0-preview.1]` with today's date, then:
      `git tag -a v2.0.0-preview.1 -m "NexusHub v2.0.0-preview.1"`
      `git push origin v2.0.0-preview.1`
      The docker-publish workflow takes over from there.

## 🟧 Deferred (allowed to slip past `-preview.1`)

These appeared in earlier reports and are tracked here so they
don't get lost, but they're not preview blockers. Promote any item
to the must-land list above if the operator decides otherwise
before the cut.

- [ ] **Dashboard redesign** — match the `dashboard-frame` layout
      from the public site (cards row, bandwidth chart, location
      donut, recent-peers table). Bigger UI work; aim for
      `preview.2` or `v2.0.0`.
- [ ] **Monitoring rollups + retention** — `peer_traffic_rollups_5m`,
      `location_traffic_rollups_5m`, `rule_hit_rollups_5m` tables
      + ingest goroutine + retention policy. Today's monitoring is
      live-only from Prometheus.
- [ ] **Mismatch warnings** — UI nudge when client routed networks
      include a CIDR no eBPF allow rule authorises, or when a
      server-side accepted route is broader than what active rules
      cover. Depends on a richer rule-introspection helper.
- [ ] **Branch protection rules on GitHub** — manual one-time setup
      in repo settings; no code lever.
- [ ] **`release-please`** — automated CHANGELOG + PR-per-release.
      The manual flow in this file works for the first preview;
      automation can land before `preview.2`.
- [ ] **Announce** — once tagged, update README badges to reflect
      the live release, write GitHub release notes from the
      CHANGELOG entry, publish blog/socials.

## Acceptance gate for `v2.0.0-preview.1`

Tag only when ALL of the following pass on a clean checkout of
`dev`:

1. `cd backend && go build ./... && go test ./...` → exit 0
2. `cd ebpf && go generate ./... && go test ./...` → exit 0
3. `cd frontend && npm install && npm run build` → exit 0
4. `docker compose -f docker/docker-compose.yml up -d` → all
   services healthy within 60 s, `/api/v1/health` returns 200
5. A peer created through the UI connects from a real WG client
   and `wg show` reflects the saved `allowed_ips`
6. Two locations + one explicit cross-location allow rule produce
   the expected ping/SSH outcome on bare metal
7. `helm install nexushub ./deploy/helm/nexushub` (against a kind
   cluster) produces a Running pod with `/health` 200
8. README badges all reflect reality; CHANGELOG's `[Unreleased]`
   header has been promoted to `[v2.0.0-preview.1]` with today's
   date
