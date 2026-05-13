# Changelog

All notable changes to NexusHub are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project follows
[Semantic Versioning](https://semver.org/) once `v2.0.0` ships. Pre-release
tags (`-preview.N`) are mutable in the sense that breaking changes between
them are expected; the public API contract freezes at `v2.0.0`.

## [Unreleased]

### Added

- **System rules subsystem** — `ebpf_rules.owner` column (migration 012)
  distinguishes admin-authored rules from auto-generated system rules.
  Cross-location deny rules are generated automatically when interfaces
  are created, address-edited, or deleted, named
  `system:deny:<a>↔<b>`. Shipped with `is_active=false` so existing
  installs aren't surprised — operator toggles them on individually or
  via the new sweep endpoints. Handler rejects DELETE on system rules
  (409) and rejects any field change other than `is_active` (409).
  Rules table shows a "system" badge + "toggle only" hint in place of
  the Edit/Delete buttons; new filter pills above the table let the
  operator narrow to All / Admin / System.
- **System-rules sweep endpoints** — `POST /api/v1/system-rules/enable-all`
  and `/disable-all` flip is_active across every owner='system' row in
  one transaction and re-apply the changes into the kernel. Rules-page
  surfaces "Enable all system rules" + "Disable all" buttons when any
  system rules exist, each with a confirmation dialog naming the
  consequence.

### Fixed

- **`direction=both` now matches symmetrically** when the rule
  constrains both src AND dst CIDRs. Previously a single rule with
  `src=10.8.0.0/24 dst=10.9.0.0/24 direction=both` only matched packets
  flowing 10.8→10.9 — the reverse direction had src=10.9.x which didn't
  match the rule's src constraint and fell through to the next rule.
  The eBPF evaluator now accepts either (src,dst) or (dst,src) when
  direction=both AND has_src AND has_dst. Other rule shapes
  (single direction, partial CIDR) keep the original asymmetric
  semantics.

### Changed

- **System-rule generator emits unordered pairs** with
  `direction='both'` instead of ordered pairs with `direction='ingress'`.
  Halves the system rule count (N×(N-1) → N×(N-1)/2) and rides on the
  new symmetric direction=both semantics. Existing system rules from
  round 16 are wiped + regenerated automatically on the next interface
  lifecycle event.

### Pending for `v2.0.0-preview.1`

- Dashboard redesign + monitoring rollups
- Docker compose end-to-end pass
- Helm chart
- Public installer script

## [v2.0.0-preview.1] — 2026-05-12

First externally testable preview of the v2.0.0 rewrite. Core control
plane is functional on bare metal; the items in **Unreleased** still
need to land before the production `v2.0.0` cut.

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
- **`ThreeLayerCallout` + `RouteSection`** components in the peer
  modals — visual separation between server-side accepted source IPs
  (filter), client routed networks (routing), and eBPF rules
  (authorization), with stripe accents and "Affects X only" banners.
- **No-CDN policy** documented in README.

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

### Fixed

- **`0.0.0.0/0` and `::/0` rejected server-side** on peer Create +
  Update. A full-tunnel server-side filter defeats per-peer source
  validation, the whole point of the WG `allowed_ips` layer.
  Migration 011 strips these from existing rows (round 14).
- **`CidrList`** inline-errors full-tunnel CIDRs when its
  `disallowFullTunnel` prop is set, mirroring the backend.
- **eBPF round-10 shadow workaround** removed — engine v2.1 supports
  overlapping CIDRs natively, so the "shadowed by X" badge can't fire.
- **Config modal `key`-bump on save** forces a fresh `/config` fetch
  the next time the operator opens it.
- **Drive-by**: dead `applyAny` in `PortField` that was breaking
  `npm run build` since the round 10 commit.

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

### Operator migration

Bare-metal deployments upgrading from a pre-preview build need:

```bash
sudo rm -rf /sys/fs/bpf/nexushub          # drop v2.0 pinned maps
cd backend && go run cmd/migrate/main.go up
# restart the backend
```

The pinned BPF maps from v2.0 have incompatible shapes; the loader
recreates the v2.1 layout on the next start. Migration 011 strips
legacy `0.0.0.0/0` / `::/0` from existing `wg_peers.allowed_ips`.
DB rows otherwise survive intact.

[Unreleased]: https://github.com/tomeksdev/NexusHub/compare/v2.0.0-preview.1...HEAD
[v2.0.0-preview.1]: https://github.com/tomeksdev/NexusHub/releases/tag/v2.0.0-preview.1
