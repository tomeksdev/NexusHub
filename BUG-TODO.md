# NexusHub Pre-Release Punch List — Round 6

Source: combined report after round 5. Two critical themes (eBPF
matching is wrong, peers can't be edited) and two polish items.

## Reference files (local only, gitignored)

- `Claude - Project Plan.md`
- `example.html`
- `hexagon_logo.png` — the official mark. We're switching from the
  round-5 inline SVG (which didn't match the brand) back to using
  this asset via cropped display so only the icon portion shows.

---

## Pass I — eBPF rule matching: src+dst is enforced as src-only  🔴critical

The kernel program (`ebpf/src/rules.c`) does an LPM lookup on the
source IP, finds a match, jumps to the rule action, and returns —
without consulting `rule_dst_v4`. A rule defined as `DENY src
10.9.0.2/32 dst 10.8.0.0/24` ends up enforcing `DENY src 10.9.0.2/32
dst any` because the destination map is never queried.

The userspace syncer correctly populates both `rule_src_v4` and
`rule_dst_v4` with the same `rule_id`. The decision logic in the
kernel is the bug.

### I1 — Add `has_src` / `has_dst` / `has_protocol` flags to `rule_meta`  ✅
Without flags the kernel can't tell apart "no destination condition
configured" from "destination configured but didn't match". Both look
like a missed lookup today.

- [ ] Extend the C `struct rule_meta` in `ebpf/headers/nexushub.h`
      with three `__u8` flag bytes (and update `_pad` to keep the
      layout aligned).
- [ ] Mirror the layout in `userspace/rules.go` Go struct + bump
      `ruleMetaSize`.
- [ ] Update Marshal/Unmarshal to ship the new bytes.
- [ ] Syncer (`ebpfkernel/syncer.go`) sets `has_src=1` when the rule
      has a `src_cidr`, `has_dst=1` for `dst_cidr`, `has_protocol=1`
      when protocol is anything but `any`.

### I2 — Fix `decide_v4` / `decide_v6` to AND-match src + dst  ✅
- [ ] When `meta->has_src` is set, fail the match if no src LPM hit
      OR src hit's rule_id ≠ meta's rule_id.
- [ ] When `meta->has_dst` is set, look up dst LPM, fail if no hit
      OR dst rule_id ≠ meta's rule_id.
- [ ] When neither is set, continue to evaluate the rule (today's
      behaviour for an "any → any" rule still works).
- [ ] Apply protocol check identically — `has_protocol=1` requires a
      matching `meta->protocol`.
- [ ] Verifier-friendliness: keep early returns, no unbounded loops
      (the existing pattern already does this).

### I3 — Regenerate bpf2go bindings  ✅
- [ ] `cd ebpf && go generate ./...` produces fresh
      `rules_x86_bpfel.go`/`rules_arm64_bpfel.go` + `.o` files.
      Both the Go source and the compiled object are committed
      (per `.gitignore` exception) so downstream builds don't need
      clang.

### I4 — Smoke-test path for the bug  ✅
- [ ] Add a small `TestRuleMatchSrcAndDst` to `ebpf/userspace/`
      that builds a spec with both src+dst CIDRs, populates maps,
      and asserts the metadata round-trips. Kernel-gated; skips on
      hosts without `CAP_BPF`.

---

## Pass J — Peer editing  🔴critical

Peers can be created and deleted. They can't be edited. Allowed
networks, the most-requested change ("user gets access to a new
subnet"), require delete-and-recreate today which rotates the keys
and breaks the user's existing config. Unacceptable for production.

### J1 — Backend `PATCH /api/v1/peers/:id`  ✅
- [ ] `repository.PeerRepo.Update(id, params)` with optional fields:
      `name`, `description`, `owner_user_id`, `allowed_ips`,
      `client_allowed_ips`, `endpoint`, `dns`, `persistent_keepalive`,
      `expires_at`, `status` (enabled/disabled). Mirrors the
      InterfaceRepo.Update shape (pointer-pointer for "clear vs.
      leave alone").
- [ ] `PeerHandler.Update` handler. Validates the same way Create
      does (CIDRs, owner-active, port/IP shape). Sends the changed
      fields into the kernel via `wgctrl.ConfigureDevice` so live
      sessions reflect the edit without a wg restart.
- [ ] Return the freshly-loaded peer row on success.

### J2 — Frontend `PeerEditModal`  ✅
- [ ] New modal mirroring the create form, pre-filled, with the
      Allowed networks field rendered as a chip list (add/remove
      individual CIDRs).
- [ ] "Edit peer" button on the peer row + inside `PeerConfigModal`.
- [ ] Save invalidates the peers query and the dashboard so the
      table reflects the change.

### J3 — Allowed-networks chip editor  ✅
- [ ] Reusable `<CidrList>` component: list current CIDRs with
      remove buttons, an input + "+ Add" button to append, parse
      validation on each add.
- [ ] Used in both `PeerCreateModal` (replaces the comma-separated
      input) and `PeerEditModal`.
- [ ] Warn (don't block) when the operator adds `0.0.0.0/0` or
      `::/0` — full-tunnel routes are valid but worth confirming.

### J4 — Config regeneration  ✅
- [ ] No new code needed; `GET /peers/:id/config` already reads
      from the DB row. Verify the QR cache (none today) doesn't
      hand out stale text after edit.
- [ ] Endpoint-port hygiene: when the location's endpoint lacks
      `:port`, the renderer must append the listen port. Today's
      code stitches the location's `endpoint` field verbatim — if
      an operator entered `nh.tomeksdev.com` without `:51820`, the
      exported `.conf` is broken. Fix the renderer.

---

## Pass K — Logo + dropdown polish  medium

### K1 — Use the official hexagon, not the inline SVG approximation  ✅
The round-5 inline SVG didn't match the brand. The user wants the
asset from `hexagon_logo.png` rendered in the sidebar — but the
asset has the "NexusHub" wordmark baked in below the icon, so we
clip to just the top hexagon portion via SVG `<image>` viewBox.

- [ ] `Logo` component renders a 32-px viewport into `/logo.png`,
      cropped to the hexagon region via SVG viewBox math. The
      wordmark below is hidden.
- [ ] Drop `public/logo.svg`; the favicon goes back to `/logo.png`
      (full image is fine in a tab; only the sidebar needs cropping).
- [ ] Document the crop coordinates in the component so a future
      brand swap is one number per side.

### K2 — Dark-theme native `<select>` dropdown  ✅
Native selects render the popup using OS chrome which doesn't honour
the body theme on Chrome/Firefox. Apply CSS `color-scheme: dark` on
form controls so the dropdown popup follows the dark theme without
needing a custom popover.

- [ ] `index.css`: `select.field-input { color-scheme: dark; }` plus
      `option { background: var(--color-surface); color: var(--color-text); }`.
- [ ] Verify the protocol picker in `RuleEditorModal` and the
      Location picker in `PeerCreateModal` both render dark.

---

## Out of scope (defer)

- Packet-simulation endpoint / "Test packet" UI — the kernel-loaded
  flag already tells operators whether the rule is in the maps, and
  the `connection_logs` ringbuf already records ACTION_LOG events.
  A simulator is a v2.1 follow-up.
- Per-peer access policy gating ("network blocked by access policy")
  — the access-rules model isn't built yet (Pass C carry-over from
  rounds past).

---

## Acceptance — round-6 boxes

- [ ] (R6) Rule `DENY src 10.9.0.2/32 dst 10.8.0.0/24` blocks
      `10.9.0.2 → 10.8.0.1` but **allows** `10.9.0.2 → 10.9.0.1`
- [ ] (R6) `bpftool map dump` shows `has_src=1 has_dst=1` for the
      same rule
- [ ] (R6) Rule `DENY src 10.9.0.2/32` (no dst) still blocks every
      destination from that source — preserves existing behaviour
- [ ] (R6) Edit peer, change allowed_ips, save, re-download `.conf`
      reflects new networks; live `wg show` reflects new
      `allowed_ips` for the session
- [ ] (R6) Sidebar logo matches the hexagon mark from
      `hexagon_logo.png`; no embedded "NexusHub" text leaks through
- [ ] (R6) Protocol picker in eBPF rule modal opens with a dark
      popup
