# Changelog

All notable changes to NexusHub are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project follows
[Semantic Versioning](https://semver.org/) once `v2.0.0` ships. Pre-release
tags (`-preview.N`) are mutable in the sense that breaking changes between
them are expected; the public API contract freezes at `v2.0.0`.

## [Unreleased]

### Added

- **`backend/internal/uifs` — embedded SPA bundle.** `//go:embed
  all:dist` pulls the built React frontend into the API binary so a
  single `nexushub-api` ships the whole control plane. Handler
  serves real files with hash-asset cache control
  (`max-age=31536000, immutable` for `/assets/*`, `no-store` for
  the entry doc), falls back to `index.html` for any unknown path
  (SPA routing), and returns a clear plain-text 503 if the bundle
  is missing instead of a generic 404. `IsEmpty()` exposed so
  diagnostics can tell "API up, UI missing" apart from "service
  down".
- **`Capabilities.PermissionDenied`** in `ebpf/userspace`. `Probe()`
  scans `ProbeErrs` for `syscall.EPERM`/`syscall.EACCES` (wrapped or
  raw) and flips the new bool. `MissingRequired()` then leads with
  `eBPF probe lacks permission (EPERM/EACCES) — container/process
  needs CAP_BPF (+ CAP_NET_ADMIN)` instead of the misleading
  "required kernel features missing" line, so Docker operators stop
  chasing kernel upgrades when the actual fix is `cap_add: BPF`.
  `Summary()` appends `(permission_denied=yes — probes blocked by
  capability/seccomp)` for the startup log line.

### Changed

- **`scripts/install.sh` prompts read from `/dev/tty`.** The
  documented one-liner (`curl ... | sudo bash`) sets stdin to the
  script stream, so the previous `-t 0` check went non-interactive
  and exited with `missing env var: NEXUSHUB_WG_ENDPOINT_HOST` even
  when there was a real operator at the terminal. Detection now
  uses `/dev/tty` readable/writable; non-interactive path
  (cloud-init, container build) still works through env vars.
- **Stable runtime directory at `/opt/nexushub`** (overridable via
  `$NEXUSHUB_RUNTIME_DIR`). Installer extracts the archive's
  `migrations/`, `env.example`, `LICENSE`, `README.md` there with
  `root:nexushub` ownership and `g+rX`; `nexushub-migrate up` and
  `nexushub-seed` run with that as their CWD. Replaces the
  preview.2 behaviour of running migrate from the operator's shell
  pwd, which the `nexushub` system user couldn't read.
- **Installer prepares bpffs + pin directory** before `systemctl
  start`. Mounts bpffs if not mounted, creates
  `/sys/fs/bpf/nexushub` with `nexushub:nexushub` ownership and
  mode `0700`. Closes the `could not create bpf pin dir —
  disabling map pinning` warning operators saw in the journal.
- **Installer health probe also checks `/`** after `/api/v1/health`.
  Non-fatal (operator might be running an API-only build), but a
  404 here prints the API-only summary block instead of a
  misleading "open the dashboard at http://..." message.
- **Docker tag matrix.** `docker-publish.yml` now publishes both
  `ghcr.io/tomeksdev/nexushub:2.0.0-preview.3` (conventional Docker
  form) and `ghcr.io/tomeksdev/nexushub:v2.0.0-preview.3` (matches
  the bare-metal `NEXUSHUB_VERSION`). `latest` + `{{major}}` +
  `{{major}}.{{minor}}` gated off pre-release tags via
  `enable=${{ !contains(github.ref, '-') }}` so a preview push
  doesn't accidentally repoint `:latest`.
- **Docker compose ships migrate + seed.** Both
  `docker/docker-compose.yml` and `docker/docker-compose.prod.yml`
  now include the one-shot migration + seed services with explicit
  `entrypoint: ["/app/nexushub-migrate"]` / `["/app/nexushub-seed"]`
  so `command:` lands on the right binary. The image's default
  `ENTRYPOINT` is the API, which previously caused migrate
  containers to start the API and bail with
  `load config: required key JWT_SECRET missing value`. The app
  service waits via `depends_on: condition:
  service_completed_successfully` so `docker compose up -d` finishes
  in the right order without manual restart.
- **Dockerfile builds frontend before the Go build.** Stage order
  reordered: `node-builder` runs first, then `go-builder` does
  `COPY --from=node-builder /build/dist/ ./backend/internal/uifs/dist/`
  before the `go build ./cmd/api/` lines. The `//go:embed`
  directive picks up the real bundle inside the Docker image — `/`
  now serves the dashboard instead of `404 page not found`. The
  runtime stage keeps the `/app/frontend/dist` copy so
  `docker-compose.prod.yml`'s Caddy + named-volume topology still
  works for operators who prefer a real web server in front of the
  API.
- **systemd unit cleanup.** `StartLimitBurst` +
  `StartLimitIntervalSec` moved from `[Service]` (where systemd
  rejects them with `Unknown key name`) to `[Unit]` where they
  belong. Inline `# comment` on `PrivateDevices=no` moved to its
  own line — systemd was parsing the whole tail as the boolean
  value and warning `Failed to parse boolean value, ignoring: no
  [...]`.

### Fixed

- **Bare-metal installer wizard runtime fixes (#79).** Closes the
  six install-flow blockers reported against `v2.0.0-preview.2`
  bare-metal testing: TTY prompts (#79 P0-1), runtime directory for
  migrations (#79 P0-2), embedded frontend (#79 P0-3), systemd unit
  parse warnings (#79 P1-4 + P1-5), bpffs preparation (#79 P1-7),
  and UI health probe (#79 P1-9).
- **Docker install-flow fixes (#81).** Closes the four blockers
  reported against `v2.0.0-preview.2` Docker testing: GHCR tag
  shape (#81 D1), compose entrypoint (#81 D2), embedded frontend
  in the image (#81 D4), and misleading eBPF probe summary in
  permission-denied environments (#81 D5).

### Known limitations

- **eBPF verifier rejects `xdp_rules` with `R7 pointer -= pointer
  prohibited`** on the operator's target kernel. The API starts
  with eBPF degraded; WireGuard control still works, rules don't
  enforce. Tracked separately; needs C-side debugging and a
  verifier-safe pointer expression rewrite in
  `ebpf/src/rules.c`. Not a `-preview.3` blocker.
- **Release-pipeline smoke test** for the published artifact (asset
  presence, frontend embedded, systemd unit parses) — would have
  caught the preview.2 gaps before publish. Deferred.

### Operator notes

Operators on `v2.0.0-preview.2` re-run the one-liner once
`v2.0.0-preview.3` is tagged:

```bash
curl -fsSL https://raw.githubusercontent.com/tomeksdev/NexusHub/main/scripts/install.sh \
  | sudo NEXUSHUB_VERSION=v2.0.0-preview.3 bash
```

The wizard preserves an existing `/etc/nexushub/env` by default,
so this is a binary + frontend upgrade with the same secrets. Pass
`NEXUSHUB_REGENERATE_ENV=1` to rotate generated secrets (requires
re-seeding peer private keys — only do this if you have to).

Docker users on the older `:2.0.0-preview.2` image either upgrade
the `NEXUSHUB_TAG` env var to `v2.0.0-preview.3` (or
`2.0.0-preview.3`), or pull `:latest` once that tag points at a
stable release. The compose files in `docker/` have been rewritten
to include migrate + seed; copy the new versions into your local
checkout if you maintain a custom compose alongside.

## [v2.0.0-preview.2] — 2026-06-02

Closes the install-flow gap that prevented `v2.0.0-preview.1`
operators from getting past the binary-download step.

### Fixed

- **Bare-metal installer publishes the asset it downloads (#79).**
  `scripts/install.sh` constructs
  `nexushub-api_<VERSION>_linux_<ARCH>.tar.gz` and `curl`s it from
  the GitHub release. The release-publishing pipeline only built
  the `nexushub` CLI, so every install hit a 404. `.goreleaser.yaml`
  now also builds `nexushub-api` + `nexushub-migrate` +
  `nexushub-seed` for `linux/{amd64,arm64}` and packages them into
  the archive the installer expects, alongside the systemd unit +
  env template + SQL migrations. The CLI archive shape is
  unchanged.

### Changed

- **`scripts/install.sh` rewritten as a setup wizard.** Detects
  TTY: interactive runs prompt for WG endpoint host/port, web port,
  PostgreSQL password, admin email/username/password (hidden input
  with double-confirm where it matters); non-interactive runs read
  every value from env vars (`NEXUSHUB_DB_PASSWORD`,
  `NEXUSHUB_WG_ENDPOINT_HOST`, ...) and exit non-zero with a clear
  missing-var error when something's absent.
- **Auto-generates the API secrets.** `JWT_SECRET` =
  `openssl rand -base64 48`, `PEER_KEY_ENCRYPTION_KEY` =
  `openssl rand -base64 32`. Operators no longer see `CHANGE_ME` in
  `/etc/nexushub/env` after a fresh install.
- **Applies the PostgreSQL password via stdin-piped `ALTER USER`** so
  the password never appears in `ps`. Existing roles are
  `ALTER`ed; no `DROP ROLE`.
- **Runs migrations + seed + service start automatically.**
  `nexushub-migrate up`, then `nexushub-seed`, then
  `systemctl restart nexushub-api`, then polls
  `/api/v1/health` for up to 30 s. Admin password passes through
  the seeder's process env only — never written to
  `/etc/nexushub/env`.
- **Tarball sha256 verification** against
  `nexushub_<VERSION>_checksums.txt` when that asset is present;
  warns + continues on older releases that predate the upload.
- **Existing `/etc/nexushub/env` preserved** across reinstalls
  unless `NEXUSHUB_REGENERATE_ENV=1` is set.
- **`deploy/systemd/env.example`** reframed as the manual-install
  template; seed-only `NEXUSHUB_ADMIN_*` lines added as
  commented-out reference with a note that the installer doesn't
  persist them.

### Operator notes

Operators who tried the bare-metal install on `v2.0.0-preview.1`
should re-run the one-liner once `v2.0.0-preview.2` is tagged:

```bash
curl -fsSL https://raw.githubusercontent.com/tomeksdev/NexusHub/main/scripts/install.sh \
  | sudo NEXUSHUB_VERSION=v2.0.0-preview.2 bash
```

The wizard preserves an existing `/etc/nexushub/env` by default,
so this is a binary upgrade with the same secrets. Pass
`NEXUSHUB_REGENERATE_ENV=1` to rotate the auto-generated secrets
(requires re-seeding peer private keys — only do this if you have
to).

Docker users are unaffected: the container image already shipped
all three binaries and the GHCR publish path works.

## [v2.0.0-preview.1] — 2026-05-18

First externally testable preview of the v2.0.0 rewrite. Core control
plane is functional on bare metal across all the flows the operator
exercises in day-to-day work (peers, locations, rules, audit log).
Dashboard redesign and monitoring rollups stay deferred for a later
preview — they aren't release blockers for a `-preview.1`.

### Added

- **eBPF rule engine v2.1** — per-packet iteration over a packed array
  via `bpf_loop`. Multiple rules per source CIDR enforce in priority
  order; the v2.0 LPM-by-source design (one rule per src CIDR) is
  retired. ADR 0005 has the full design. Minimum kernel: 5.17.
- **Per-rule kernel hit counters** — surfaced in the Rules table so
  operators can answer "rule LOADED but is it seeing traffic?".
- **`bpf_loop` capability probe** in `ebpf/userspace.Capabilities`;
  startup logs `bpf_loop=ok|missing` and fails fast with a clear error
  on unsupported kernels.
- **System rules subsystem** — `ebpf_rules.owner` column (migration
  012) distinguishes admin-authored rules from auto-generated system
  rules. Cross-location deny rules are generated automatically when
  interfaces are created, address-edited, or deleted, named
  `system:deny:<a>↔<b>`. New pairs default to `is_active=true` so the
  cross-location default-deny baseline is active from the moment the
  second location lands; operator overrides survive regeneration.
  Handler rejects DELETE on system rules (409) and rejects any field
  change other than `is_active` (409). Rules table shows a "system"
  badge + "toggle only" hint in place of the Edit/Delete buttons;
  filter pills above the table narrow to All / Admin / System.
- **System-rules sweep endpoints** — `POST /api/v1/system-rules/enable-all`
  and `/disable-all` flip is_active across every owner='system' row in
  one transaction and re-apply the changes into the kernel.
  Rules page surfaces matching buttons with confirmation dialogs.
- **`ThreeLayerCallout` + `RouteSection`** components in the peer
  modals — visual separation between server-side accepted source IPs
  (filter), client routed networks (routing), and eBPF rules
  (authorization), with stripe accents and "Affects X only" banners.
- **No-CDN policy** documented in README; reverse-proxy CSP template
  and seven-step operational verification checklist in
  `docs/DEPLOYMENT.md`.
- **`docs/DEVELOPMENT.md`** + **`docs/DEPLOYMENT.md`** — top-level
  contributor and operations playbooks.

### Changed

- **Peer `allowed_ips`** auto-includes the assigned `/32` (or `/128`)
  in both Create and Update. Operators can no longer lock themselves
  out by saving a server-side filter that doesn't cover the peer's
  own source IP.
- **Peer edit PATCH semantics** switched from "diff against the prop
  snapshot, omit unchanged fields" to "always send the operator's
  current state". The diff approach skipped writes whenever the prop
  was stale relative to a background refetch.
- **Peer list "Networks" column → "Client routes"** with a tooltip
  spelling out that the value is the exported `.conf` AllowedIPs, NOT
  `wg show`.
- **Configuration sidebar section hidden** (Global Config / Groups /
  Access Rules) until those features ship. Stub routes remain so
  bookmarks resolve to a "coming in v2.1" page.
- **`direction=both` now matches symmetrically** when the rule
  constrains both src AND dst CIDRs. A single rule with
  `src=10.8.0.0/24 dst=10.9.0.0/24 direction=both` covers both
  A→B and B→A traffic.
- **System-rule generator emits unordered pairs** with
  `direction='both'` instead of ordered pairs with
  `direction='ingress'`. Halves the rule count (N×(N-1) → N×(N-1)/2)
  and rides on the new symmetric matching.
- **Kernel reconciles atomically with regenerate**: after
  RegenerateSystemDenies, InterfaceHandler calls Syncer.Reconcile
  with the full active-rule snapshot so eBPF maps converge in the
  same HTTP request that created/modified the location.
- **Runtime image switched to `gcr.io/distroless/static-debian12:nonroot`**
  from `debian:bookworm-slim`. The previous base was the source of
  ~220 container CVE alerts (libssh2, libcurl, gnutls, krb5).
  Distroless ships only ca-certificates, tzdata, and the nonroot user
  — no shell, no package manager, no system libs. Go binaries stay
  statically linked under `CGO_ENABLED=0`; HEALTHCHECK invokes a new
  `nexushub -health` flag that hits its own `/health` endpoint via
  net/http and exits 0/1.
- **`internal/dbtest` gated behind `//go:build integration`** so
  testcontainers + docker/docker drop out of the production build
  graph entirely. Verified: `go list -deps ./cmd/api | grep docker`
  is empty.

### Fixed

- **`0.0.0.0/0` and `::/0` rejected server-side** on peer Create +
  Update. A full-tunnel server-side filter defeats per-peer source
  validation, the whole point of the WG `allowed_ips` layer.
  Migration 011 strips these from existing rows.
- **`CidrList`** inline-errors full-tunnel CIDRs when its
  `disallowFullTunnel` prop is set, mirroring the backend.
- **eBPF round-10 shadow workaround** removed — engine v2.1 supports
  overlapping CIDRs natively, so the "shadowed by X" badge can't fire.
- **Config modal `key`-bump on save** forces a fresh `/config` fetch
  the next time the operator opens it.
- **`PortField`** dead useEffect that re-initialised state from props
  on mount removed (useState initializers already capture mount-time
  props); dead `applyAny` + `formatPortRange` exports removed.
- **CI lint floor passes**: gofmt across 8 files, misspell fixes
  (defence/honoured/initialised), errcheck wrappers, staticcheck
  simplification in `wg/link.go`, dead `parsePrefixes` removed.

### Removed

- LPM-trie maps `rule_src_v4`, `rule_src_v6`, `rule_dst_v4`,
  `rule_dst_v6`, `rule_meta` (replaced by `rule_table_v4` /
  `rule_table_v6` packed arrays).
- `userspace.RuleMeta` struct + `PutRuleMeta` / `PutSrcPrefix` /
  `PutDstPrefix` helpers (replaced by `RuleV4Record` / `RuleV6Record`
  + `PutRuleV4` / `PutRuleV6` / `SetRuleCountV4` / `SetRuleCountV6`).
- `Capabilities.HasLPMTrie` retired; `HasBPFLoop` added.
- "+ Copy server-side routes here" button from the peer edit modal —
  added in round 10 as a UX helper, removed in round 13 because it
  helped conflate the two route fields in operator mental models.
- `shadowed_by_rule_name` field from `ruleResponse` (along with the
  frontend Shadowed badge).

### Security

- **2 Dependabot Moby alerts** (CVE-2026-33997 + CVE-2026-34040)
  dismissed as `tolerable_risk`. docker/docker only enters the build
  graph through testcontainers, which is now `//go:build integration`
  gated; production binaries don't link it.
- **2 code-scanning go.mod alerts** dismissed for the same reason.

### Operator migration

Bare-metal deployments upgrading from a pre-preview build need:

```bash
sudo rm -rf /sys/fs/bpf/nexushub          # drop v2.0 pinned maps
cd backend && go run ./cmd/migrate up
# restart the backend
```

The pinned BPF maps from v2.0 have incompatible shapes; the loader
recreates the v2.1 layout on the next start. Migrations 011 + 012
land along with the binary update:
- Migration 011 strips legacy `0.0.0.0/0` / `::/0` from existing
  `wg_peers.allowed_ips`.
- Migration 012 adds `ebpf_rules.owner`; existing rules grandfather
  as `owner='admin'`.

DB rows otherwise survive intact.

[Unreleased]: https://github.com/tomeksdev/NexusHub/compare/v2.0.0-preview.2...HEAD
[v2.0.0-preview.2]: https://github.com/tomeksdev/NexusHub/releases/tag/v2.0.0-preview.2
[v2.0.0-preview.1]: https://github.com/tomeksdev/NexusHub/releases/tag/v2.0.0-preview.1
