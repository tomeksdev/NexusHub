# Changelog

All notable changes to NexusHub are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project follows
[Semantic Versioning](https://semver.org/) once `v2.0.0` ships. Pre-release
tags (`-preview.N`) are mutable in the sense that breaking changes between
them are expected; the public API contract freezes at `v2.0.0`.

## [Unreleased]

_Nothing yet — every blocker for `v2.0.0-preview.1` shipped below._

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

[Unreleased]: https://github.com/tomeksdev/NexusHub/compare/v2.0.0-preview.1...HEAD
[v2.0.0-preview.1]: https://github.com/tomeksdev/NexusHub/releases/tag/v2.0.0-preview.1
